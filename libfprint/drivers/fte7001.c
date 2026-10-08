/*
 * FocalTech FTE7001 / FT9338 SPI fingerprint driver
 *
 * Based on fte3600.c.  FT9338 is a match-on-host sensor in the same
 * FocalTech 93xx family.  Key differences from FT9361:
 *   - RAM-loaded firmware: no on-chip boot ROM for the sensor stack.
 *     After S5 power loss the chip sits in A-CUT boot and img_open()
 *     downloads the 14136 B blob (05 FA), verifies it (04 FB), then
 *     double-resets the chip to make it execute (2026-10-06).
 *   - No 0x76 CAPTURE_MODE register
 *   - 0x30 gate: read 0x30 (verify 0xBB) immediately before 04FB capture
 *   - Image: 88 x 88 = 7744 B  (vs. 64 x 80 = 5120 B)
 *   - Finger detection polls 0x1D (GPIO 86 never fires on Linux)
 *   - ReturnAutoPower rearm: 0x20 read → 0x54 write → 0x20 read
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "fte7001.h"
#include "drivers_api.h"
#include "fte7001-matcher.h"

#include <errno.h>
#include <fcntl.h>
#include <gpiod.h>
#include <gudev/gudev.h>
#include <linux/spi/spidev.h>
#include <math.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/utsname.h>

/* Embedded FT9338 cold-boot firmware blob (Windows cold-boot capture verified, 14136 B) */
#include "ft9338-firmware.inc"

#define FP_COMPONENT "fte7001"

/* ----- GPIO profiles (OneMix3) ----- */
static const Fte7001GpioProfile fte7001_gpio_profiles[] = {
  { .sys_vendor = "One Netbook Technology Co., Ltd.",
    .product_name = "One Mix 3",
    .controller_acpi_path = "\\_SB_.PCI0.GPI0",
    .controller_hid = "INT3450",
    .reset_offset = 85,
    .irq_offset = 86,
  },
  { .sys_vendor = "Acidanthera",
    .product_name = "MacBookAir8,1",
    .controller_acpi_path = "\\_SB_.PCI0.GPI0",
    .controller_hid = "INT3450",
    .reset_offset = 85,
    .irq_offset = 86,
  },
  { NULL, NULL, NULL, NULL, 0, 0 }
};

const Fte7001GpioProfile *
fpi_fte7001_lookup_gpio_profile (const gchar *sys_vendor,
                                 const gchar *product_name)
{
  for (const Fte7001GpioProfile *p = fte7001_gpio_profiles; p->sys_vendor; p++)
    if (g_strcmp0 (sys_vendor, p->sys_vendor) == 0 &&
        g_strcmp0 (product_name, p->product_name) == 0)
      return p;
  return NULL;
}

/* ----- Device struct ----- */
struct _FpiDeviceFte7001
{
  FpDevice           parent;

  /* SPI */
  gint              spi_fd;
  guint8            small_rx[FT9338_SMALL_FRAME_SIZE];
  gboolean          small_rx_valid;
  guint8           *capture_tx;
  guint8           *capture_rx;
  gint64            capture_deadline;

  /* GPIO */
  const Fte7001GpioProfile *gpio_profile;
  struct gpiod_line_request *gpio_request;

  /* State */
  guint             false_finger_count;
  FpiSsm           *task_ssm;

  /* Cold init */
  gboolean          cold_path;         /* TRUE when A-CUT boot detected */
  guint             fe_round;          /* FE check loop counter */
  guint             warm_retries;      /* warm-path MCU idle re-reads before falling to cold */
  guint16           chip_id;
  guint8           *fw_write_buf;      /* 05 FA transfer buffer (header+blob+tail) */
  guint8           *fw_readback_buf;  /* 04 FB RX buffer */

  /* Form B (FpDevice) action state */
  guint             gate_rearm_count;      /* 0x30 gate re-ARM budget per stage */
  guint             enroll_stage;           /* 0..FT9338_ENROLL_STAGES-1 */
  guint             quality_retries;        /* per-stage quality-gate re-captures */
  gboolean          image_handed_over;      /* frame consumed; cleanup errors only logged */
  gint64            wait_off_start;         /* WAIT_OFF round start (2 s cap) */
  guint             wait_off_lift_count;    /* consecutive no-finger frames */
  Fte7001Frame     *enroll_frames[FT9338_ENROLL_STAGES];
  FpPrint          *enroll_print;           /* template container from fpi_device_get_enroll_data */
  Fte7001Frame      verify_probe;            /* single probe frame (form B) */
  gboolean          verify_probe_valid;
  gchar            *spidev_cached;           /* re-open fallback (fprintd Claim cycles) */
  GCancellable     *worker_cancellable;     /* matcher GTask */
};

G_DECLARE_FINAL_TYPE (FpiDeviceFte7001, fpi_device_fte7001, FPI, DEVICE_FTE7001, FpDevice)
G_DEFINE_TYPE (FpiDeviceFte7001, fpi_device_fte7001, FP_TYPE_DEVICE)

/* ----- helpers ----- */
static guint8
fte7001_read_result_byte (FpiDeviceFte7001 *self)
{
  return self->small_rx[FT9338_REG_READ_HEADER_SIZE];
}

/* TRUE if any byte in buf[:len] is non-zero (suspend detection). */
static inline gboolean
fte7001_buf_has_data (const guint8 *buf, gsize len)
{
  for (gsize i = 0; i < len; i++)
    if (buf[i] != 0)
      return TRUE;
  return FALSE;
}

static gboolean
fte7001_mcu_is_idle (FpiDeviceFte7001 *self)
{
  return self->small_rx_valid &&
         self->small_rx[FT9338_REG_READ_HEADER_SIZE] == 0xa5 &&
         self->small_rx[FT9338_REG_READ_HEADER_SIZE + 1] == 0x5a;
}

/* ----- SPI transfer helpers ----- */
static void
fte7001_submit_transfer (FpiSsm *ssm, FpiSpiTransfer *transfer, gboolean cancellable)
{
  GCancellable *c = cancellable ? fpi_device_get_cancellable (fpi_ssm_get_device (ssm)) : NULL;

  fpi_spi_transfer_submit (transfer, c, fpi_ssm_spi_transfer_cb, NULL);
  transfer->ssm = ssm;
}

/* Write-only frame (path-2 equivalent): 55 AA (2B), 70 (1B), 05 FA.
 * No read phase — matches Windows WdfIoTargetSendWriteSynchronously. */
static void
fte7001_submit_write_only (FpiSsm *ssm, const guint8 *data, gsize len)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (fpi_ssm_get_device (ssm));
  FpiSpiTransfer *transfer;

  self->small_rx_valid = FALSE;
  transfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);
  fpi_spi_transfer_write (transfer, len);
  memcpy (transfer->buffer_wr, data, len);
  fte7001_submit_transfer (ssm, transfer, FALSE);
}

static void
fte7001_reg_read_cb (FpiSpiTransfer *transfer, FpDevice *device,
                     gpointer unused, GError *error)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (device);

  (void) unused;
  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, g_error_copy (error));
      return;
    }
  self->small_rx_valid = TRUE;
  fpi_ssm_next_state (transfer->ssm);
}

/* 08 F7 <reg> 00 — short-config read (4B/4B full-duplex).
 * Value offset is register-dependent: CB in rx[3], C2 in rx[0]. */
static void
fte7001_submit_short_read (FpiSsm *ssm, guint8 reg, gboolean cancellable)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (fpi_ssm_get_device (ssm));
  FpiSpiTransfer *transfer;

  self->small_rx_valid = FALSE;
  memset (self->small_rx, 0, 4);

  transfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);
  fpi_spi_transfer_write (transfer, 4);
  transfer->buffer_wr[0] = 0x08;
  transfer->buffer_wr[1] = 0xf7;
  transfer->buffer_wr[2] = reg;
  transfer->buffer_wr[3] = 0x00;
  fpi_spi_transfer_read_full (transfer, self->small_rx, 4, NULL);
  fpi_spi_transfer_set_full_duplex (transfer, TRUE);
  transfer->ssm = ssm;
  fpi_spi_transfer_submit (
    transfer,
    cancellable ? fpi_device_get_cancellable (FP_DEVICE (self)) : NULL,
    fte7001_reg_read_cb, NULL);
}

/* 09 F6 <reg> <val> — short-config write.  The Windows capture shows all 09 F6 writes
 * as opcode=09f6 expRX=4 (full-duplex, response 00 00 00 00), NOT write-only.
 * Only 55 AA / 70 / 05 FA are write-only (PATH2). */
static void
fte7001_submit_short_write (FpiSsm *ssm, guint8 reg, guint8 val,
                            gboolean cancellable)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (fpi_ssm_get_device (ssm));
  FpiSpiTransfer *transfer;

  self->small_rx_valid = FALSE;
  memset (self->small_rx, 0, 4);

  transfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);
  fpi_spi_transfer_write (transfer, 4);
  transfer->buffer_wr[0] = 0x09;
  transfer->buffer_wr[1] = 0xf6;
  transfer->buffer_wr[2] = reg;
  transfer->buffer_wr[3] = val;
  fpi_spi_transfer_read_full (transfer, self->small_rx, 4, NULL);
  fpi_spi_transfer_set_full_duplex (transfer, TRUE);
  transfer->ssm = ssm;
  fpi_spi_transfer_submit (
    transfer,
    cancellable ? fpi_device_get_cancellable (FP_DEVICE (self)) : NULL,
    fte7001_reg_read_cb, NULL);
}

/* 90 00 00 — A-CUT boot detect (3B/3B full-duplex).  RX[2]==0xEF. */
static void
fte7001_submit_acut_detect (FpiSsm *ssm)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (fpi_ssm_get_device (ssm));
  FpiSpiTransfer *transfer;

  self->small_rx_valid = FALSE;
  memset (self->small_rx, 0, 3);

  transfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);
  fpi_spi_transfer_write (transfer, 3);
  transfer->buffer_wr[0] = 0x90;
  transfer->buffer_wr[1] = 0x00;
  transfer->buffer_wr[2] = 0x00;
  fpi_spi_transfer_read_full (transfer, self->small_rx, 3, NULL);
  fpi_spi_transfer_set_full_duplex (transfer, TRUE);
  transfer->ssm = ssm;
  fpi_spi_transfer_submit (
    transfer,
    fpi_device_get_cancellable (FP_DEVICE (self)),
    fte7001_reg_read_cb, NULL);
}

/* 05 FA block write (write-only, 14143 B = 6 header + blob + 1 tail). */
static void
fte7001_submit_firmware_write (FpiSsm *ssm)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (fpi_ssm_get_device (ssm));
  FpiSpiTransfer *transfer;

  transfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);
  fpi_spi_transfer_write_full (transfer, self->fw_write_buf,
                               6 + FT9338_FW_BLOB_SIZE + 1, NULL);
  fte7001_submit_transfer (ssm, transfer, TRUE);
}

/* 04 FB readback (full-duplex, 14144 B).  TX 7-byte cmd + zero padding. */
static void
fte7001_submit_firmware_readback (FpiSsm *ssm)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (fpi_ssm_get_device (ssm));
  FpiSpiTransfer *transfer;

  memset (self->fw_readback_buf, 0, FT9338_FW_READBACK_RX);
  transfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);
  fpi_spi_transfer_write (transfer, FT9338_FW_READBACK_RX);
  transfer->buffer_wr[0] = 0x04;
  transfer->buffer_wr[1] = 0xfb;
  transfer->buffer_wr[2] = FT9338_FW_ADDR_HIGH;
  transfer->buffer_wr[3] = FT9338_FW_ADDR_LOW;
  transfer->buffer_wr[4] = 0x37;   /* len hi: 0x373A = 14138 */
  transfer->buffer_wr[5] = 0x3a;   /* len lo */
  transfer->buffer_wr[6] = 0x00;
  fpi_spi_transfer_read_full (transfer, self->fw_readback_buf,
                              FT9338_FW_READBACK_RX, NULL);
  fpi_spi_transfer_set_full_duplex (transfer, TRUE);
  fte7001_submit_transfer (ssm, transfer, TRUE);
}

static void
fte7001_submit_reg_read (FpiSsm *ssm, guint8 reg, guint8 result_len,
                         gboolean cancellable)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (fpi_ssm_get_device (ssm));
  FpiSpiTransfer *transfer;
  gsize frame_len = FT9338_REG_READ_HEADER_SIZE + result_len;

  g_assert (frame_len <= sizeof (self->small_rx));
  self->small_rx_valid = FALSE;
  memset (self->small_rx, 0, frame_len);

  transfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);
  fpi_spi_transfer_write (transfer, frame_len);
  transfer->buffer_wr[0] = 0x10;
  transfer->buffer_wr[1] = 0xef;
  transfer->buffer_wr[2] = reg;
  transfer->buffer_wr[3] = 0x00;
  fpi_spi_transfer_read_full (transfer, self->small_rx, frame_len, NULL);
  fpi_spi_transfer_set_full_duplex (transfer, TRUE);
  transfer->ssm = ssm;
  fpi_spi_transfer_submit (
    transfer,
    cancellable ? fpi_device_get_cancellable (FP_DEVICE (self)) : NULL,
    fte7001_reg_read_cb, NULL);
}

static void
fte7001_submit_reg_write (FpiSsm *ssm, guint8 reg, guint8 value,
                          gboolean cancellable)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (fpi_ssm_get_device (ssm));
  FpiSpiTransfer *transfer;

  self->small_rx_valid = FALSE;
  transfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);
  fpi_spi_transfer_write (transfer, FT9338_REG_WRITE_SIZE);
  transfer->buffer_wr[0] = 0x11;
  transfer->buffer_wr[1] = 0xee;
  transfer->buffer_wr[2] = reg;
  transfer->buffer_wr[3] = value;
  transfer->buffer_wr[4] = 0x00;
  fte7001_submit_transfer (ssm, transfer, cancellable);
}

static void
fte7001_submit_capture (FpiSsm *ssm)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (fpi_ssm_get_device (ssm));
  FpiSpiTransfer *transfer;

  memset (self->capture_rx, 0, FT9338_CAPTURE_FRAME_SIZE);
  transfer = fpi_spi_transfer_new (FP_DEVICE (self), self->spi_fd);
  fpi_spi_transfer_write_full (transfer, self->capture_tx,
                               FT9338_CAPTURE_FRAME_SIZE, NULL);
  fpi_spi_transfer_read_full (transfer, self->capture_rx,
                              FT9338_CAPTURE_FRAME_SIZE, NULL);
  fpi_spi_transfer_set_full_duplex (transfer, TRUE);
  fpi_spi_transfer_set_sensitive (transfer, TRUE);
  fte7001_submit_transfer (ssm, transfer, TRUE);
}

/* ----- GPIO ----- */
static void
fte7001_set_hardware_reset (FpiSsm *ssm, FpiDeviceFte7001 *self, gboolean asserted)
{
  enum gpiod_line_value value;

  g_assert (self->gpio_request != NULL);
  g_assert (self->gpio_profile != NULL);

  /* GPIO 85 is active-low: raw 0 = assert reset */
  value = asserted ? GPIOD_LINE_VALUE_INACTIVE : GPIOD_LINE_VALUE_ACTIVE;
  if (gpiod_line_request_set_value (self->gpio_request,
                                    self->gpio_profile->reset_offset, value) < 0)
    {
      fpi_ssm_mark_failed (ssm,
        g_error_new (G_IO_ERROR, g_io_error_from_errno (errno),
                     "fte7001 reset GPIO failed: %s", g_strerror (errno)));
      return;
    }
  fpi_ssm_next_state (ssm);
}

static void
fte7001_release_gpio (FpiDeviceFte7001 *self)
{
  if (self->gpio_request)
    {
      gpiod_line_request_release (self->gpio_request);
      self->gpio_request = NULL;
    }
}

/* ----- Probe / open / close ----- */
static gboolean
fte7001_probe_acpi (FpiDeviceFte7001 *self, const gchar *spidev_path)
{
  /* spidev_path is a devnode like "/dev/spidev0.0" — extract device name */
  const gchar *devname = strrchr (spidev_path, '/');
  devname = devname ? devname + 1 : spidev_path;

  g_autofree gchar *modalias_path = NULL;
  g_autofree gchar *modalias = NULL;
  g_autofree gchar *sys_vendor = NULL;
  g_autofree gchar *product_name = NULL;
  const Fte7001GpioProfile *profile;

  modalias_path = g_strdup_printf ("/sys/class/spidev/%s/device/modalias",
                                   devname);
  if (!g_file_get_contents (modalias_path, &modalias, NULL, NULL))
    return FALSE;
  if (!g_str_has_prefix (modalias, "acpi:FTE7001:"))
    return FALSE;

  if (!g_file_get_contents ("/sys/class/dmi/id/sys_vendor", &sys_vendor, NULL, NULL) ||
      !g_file_get_contents ("/sys/class/dmi/id/product_name", &product_name, NULL, NULL))
    return FALSE;

  g_strstrip (sys_vendor);
  g_strstrip (product_name);
  profile = fpi_fte7001_lookup_gpio_profile (sys_vendor, product_name);
  if (!profile)
    {
      fp_dbg ("FTE7001 unsupported DMI: %s / %s", sys_vendor, product_name);
      return FALSE;
    }

  self->gpio_profile = profile;
  return TRUE;
}

static gboolean
fte7001_determine_spidev_speed (FpiDeviceFte7001 *self, GError **error)
{
  guint32 speed = 0;

  /* FT9338 is only characterised at 1 MHz on this platform.  The
   * controller ceiling reported by spidev can be far higher (LPSS
   * controllers advertise tens of MHz); never program that — clamp to
   * the known-good rate from the header. */
  if (ioctl (self->spi_fd, SPI_IOC_RD_MAX_SPEED_HZ, &speed) != 0 ||
      speed == 0 || speed > FTE7001_SPI_SPEED_HZ)
    speed = FTE7001_SPI_SPEED_HZ;

  if (ioctl (self->spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed) != 0)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
                   "FTE7001: cannot set SPI speed %u Hz: %s",
                   speed, g_strerror (errno));
      return FALSE;
    }
  return TRUE;
}

static gboolean
fte7001_take_gpio (FpiDeviceFte7001 *self, GError **error)
{
  struct gpiod_line_settings *settings;
  struct gpiod_line_config *config;
  struct gpiod_request_config *req_cfg;
  struct gpiod_chip *chip;
  g_autofree gchar *chip_path = NULL;

  settings = gpiod_line_settings_new ();
  gpiod_line_settings_set_direction (settings, GPIOD_LINE_DIRECTION_OUTPUT);
  gpiod_line_settings_set_output_value (settings, GPIOD_LINE_VALUE_ACTIVE);

  config = gpiod_line_config_new ();
  gpiod_line_config_add_line_settings (config,
      &self->gpio_profile->reset_offset, 1, settings);
  req_cfg = gpiod_request_config_new ();
  gpiod_request_config_set_consumer (req_cfg, "fte7001");

  chip_path = g_strdup ("/dev/gpiochip0");
  chip = gpiod_chip_open (chip_path);
  if (!chip)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
                   "fte7001 could not open GPIO chip %s: %s",
                   chip_path, g_strerror (errno));
      gpiod_line_settings_free (settings);
      gpiod_line_config_free (config);
      gpiod_request_config_free (req_cfg);
      return FALSE;
    }

  self->gpio_request = gpiod_chip_request_lines (chip, req_cfg, config);
  /* The chip handle is only needed to create the request; close it on
   * every path so it does not leak (the request stays valid). */
  gpiod_chip_close (chip);
  gpiod_line_settings_free (settings);
  gpiod_line_config_free (config);
  gpiod_request_config_free (req_cfg);

  if (!self->gpio_request)
    {
      g_set_error (error, G_IO_ERROR, g_io_error_from_errno (errno),
                   "fte7001 could not claim GPIO chip %s: %s",
                   chip_path, g_strerror (errno));
      return FALSE;
    }
  return TRUE;
}

/* ----- State machine forward declarations and enums ----- */
static void fte7001_init_handler (FpiSsm *ssm, FpDevice *dev);
static void fte7001_init_complete (FpiSsm *ssm, FpDevice *dev, GError *error);

enum fte7001_init_state {
  /* Universal first probe: 90 00 00 3B full-duplex.
   * Preceded by warm-probe preamble (Windows capture frames 1-11):
   *   10 EF 20 + 70 wr ×4 + 10 EF 20/16/17
   * These frames establish initial chip state even though
   * the responses are garbage/echo on cold boot. */
  FTE7001_INIT_PREAMBLE_10EF20_1,
  FTE7001_INIT_PREAMBLE_70_1,
  FTE7001_INIT_PREAMBLE_70_2,
  FTE7001_INIT_PREAMBLE_70_3,
  FTE7001_INIT_PREAMBLE_70_4,
  FTE7001_INIT_PREAMBLE_10EF20_2,
  FTE7001_INIT_PREAMBLE_10EF16,
  FTE7001_INIT_PREAMBLE_10EF17,
  FTE7001_INIT_ACUT_DETECT,
  FTE7001_INIT_ACUT_CHECK,
  /* Warm path: chip already alive (10 EF 20 → A5 5A) */
  FTE7001_INIT_WARM_READ_MCU,
  FTE7001_INIT_WARM_CHECK_MCU,
  /* Cold path: hardware reset (assert 10 ms → deassert → settle 50 ms) */
  FTE7001_INIT_COLD_RESET_ASSERT,
  FTE7001_INIT_COLD_RESET_HOLD,
  FTE7001_INIT_COLD_RESET_DEASSERT,
  FTE7001_INIT_COLD_SETTLE,
  /* Cold path: 55 AA → 0xFE existence check loop (5 rounds) */
  FTE7001_INIT_COLD_55AA,
  FTE7001_INIT_COLD_FE_CB_READ,
  FTE7001_INIT_COLD_FE_CB_WRITE,
  FTE7001_INIT_COLD_FE_FD_WRITE,
  FTE7001_INIT_COLD_FE_FE_WRITE,
  FTE7001_INIT_COLD_FE_READ,
  FTE7001_INIT_COLD_FE_CHECK,
  FTE7001_INIT_COLD_FE_DELAY,
  /* Cold path: 10 EF 20 read + 70 wr ×2 alternation (Windows capture frames 43-48,
   * exit sensormode before download) ×3, then 55 AA #6 */
  /* The Windows capture has a D0Entry (D5→D0 power transition) between FE loop and the
   * 10EF20 block — it re-inits SPI+GPIO, i.e. one more GPIO reset. */
  FTE7001_INIT_COLD_D0_RESET_ASSERT,
  FTE7001_INIT_COLD_D0_RESET_HOLD,
  FTE7001_INIT_COLD_D0_RESET_DEASSERT,
  FTE7001_INIT_COLD_FW_10EF20_1,
  FTE7001_INIT_COLD_FW_70a_1,
  FTE7001_INIT_COLD_FW_70a_2,
  FTE7001_INIT_COLD_FW_10EF20_2,
  FTE7001_INIT_COLD_FW_70b_1,
  FTE7001_INIT_COLD_FW_70b_2,
  FTE7001_INIT_COLD_FW_10EF20_3,
  /* Cold path: 55 AA #6 — firmware-branch entry (after sensormode exit) */
  FTE7001_INIT_COLD_FW_55AA,
  /* Cold path: C2 identification (C2 rx[0]==0x02 → FT9338) */
  FTE7001_INIT_COLD_C2_WRITE,
  FTE7001_INIT_COLD_C2_READ,
  FTE7001_INIT_COLD_C2_CHECK,
  /* Cold path: download mode (09 F6 C8→CA→CB→B9×2) */
  FTE7001_INIT_COLD_DL_C8,
  FTE7001_INIT_COLD_DL_CA,
  FTE7001_INIT_COLD_DL_CB,
  FTE7001_INIT_COLD_DL_B9A,
  FTE7001_INIT_COLD_DL_B9B,
  /* Cold path: firmware 05 FA write + 04 FB readback + content check */
  FTE7001_INIT_COLD_FW_WRITE,
  FTE7001_INIT_COLD_FW_READBACK,
  /* Verify the 04 FB payload byte-for-byte against the blob.  The frame
   * carries a receipt header, so the blob start offset varies: locate it
   * by matching the first 64 blob bytes anywhere in the readback buffer
   * (off ≤ READBACK_RX - BLOB_SIZE), then memcmp the whole blob (same
   * approach as fp-unlock.py). */
  FTE7001_INIT_COLD_FW_READBACK_CHECK,
  /* Cold path: chip restart after firmware download.
   * Windows DownLoadFirewareInternal 0x001665-0x0016AB (chip_type==1):
   *   Sleep(2) → rst pulse#1 (low 7 ms → high) → Sleep(10)
   *   → rst pulse#2 (low 7 ms → high) → Sleep(180) → probe.
   * Without this the written firmware never executes (verified: chip
   * stays silent after 05 FA + 04 FB unless hard-reset). */
  FTE7001_INIT_COLD_FW_RST2MS,
  FTE7001_INIT_COLD_FW_RST1_ASSERT,
  FTE7001_INIT_COLD_FW_RST1_HOLD,
  FTE7001_INIT_COLD_FW_RST1_DEASSERT,
  FTE7001_INIT_COLD_FW_RST10MS,
  FTE7001_INIT_COLD_FW_RST2_ASSERT,
  FTE7001_INIT_COLD_FW_RST2_HOLD,
  FTE7001_INIT_COLD_FW_RST2_DEASSERT,
  FTE7001_INIT_COLD_FW_RST180MS,
  /* Cold path: 10 EF 20 after firmware (Windows capture frame 60) */
  FTE7001_INIT_COLD_FW_10EF20,
  /* Cold path: sensor ID verify (0x14→0x58, 0x15→0x58, hard check).
   * Values are read at RX[4] (FT9338_REG_READ_HEADER_SIZE): the Windows
   * driver's ctx default is 0x5858 (movw $0x5858 @0x180002e2e), and the
   * P5-G wire capture shows 10 EF 15 → RX 58 10 93 93 58 (RX[4]=0x58). */
  FTE7001_INIT_COLD_SENSOR_H,
  FTE7001_INIT_COLD_SENSOR_L,
  FTE7001_INIT_COLD_SENSOR_CHECK,
  /* Shared config init: 11 EE 01 → 41 0F → 30 BB → 22 00 → 23 0E.
   * WARM-ONLY GATE: when the marker already reads 0xBB the chip is armed
   * and rewriting the config registers destroys the finger-ready status
   * (RX[4] of 0x1D never reaches 0x01 afterwards — verified 2026-10-07:
   * two fprintd-enroll runs deadlocked exactly here while the production
   * fp-unlock.py path, which skips these writes when 0x30==0xBB, captures
   * fine).  So: read 0x30 first; already 0xBB → jump straight to ARM. */
  FTE7001_INIT_GATE_READ_30,
  FTE7001_INIT_GATE_CHECK_30,
  FTE7001_INIT_WRITE_01,
  FTE7001_INIT_DELAY_01,
  FTE7001_INIT_WRITE_41,
  FTE7001_INIT_DELAY_41,
  FTE7001_INIT_WRITE_30,
  FTE7001_INIT_DELAY_30,
  FTE7001_INIT_VERIFY_30,
  FTE7001_INIT_CHECK_30,
  FTE7001_INIT_WRITE_22,
  FTE7001_INIT_DELAY_22,
  FTE7001_INIT_WRITE_23,
  FTE7001_INIT_DELAY_23,
  FTE7001_INIT_FINAL_MCU,
  FTE7001_INIT_CHECK_FINAL,
  FTE7001_INIT_DONE,
  FTE7001_INIT_NSTATES,
};

static void
fte7001_open (FpDevice *dev)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (dev);
  g_autofree gchar *spidev_path = NULL;
  GError *error = NULL;

  /* Cache the spidev path on first successful open: the framework may
   * hand us a NULL udev path on re-open inside the same daemon lifetime
   * (Claim→Release→Claim cycles, 2026-10-07 fprintd evidence: second
   * open after close reported NOT_SUPPORTED and crashed fprintd's
   * Claim error path with a double free). */
  spidev_path = g_strdup (fpi_device_get_udev_data (dev, FPI_DEVICE_UDEV_SUBTYPE_SPIDEV));
  if (!spidev_path && self->spidev_cached)
    spidev_path = g_strdup (self->spidev_cached);
  if (!spidev_path || !fte7001_probe_acpi (self, spidev_path))
    {
      fpi_device_open_complete (dev,
        fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                   "FTE7001: unknown or unsupported platform"));
      return;
    }

  if (!fte7001_take_gpio (self, &error))
    {
      fpi_device_open_complete (dev, error);
      return;
    }

  self->spi_fd = open (spidev_path, O_RDWR);
  if (self->spi_fd < 0)
    {
      /* Open failed before the SSM exists: the framework will not call
       * close, so release the GPIO claimed above ourselves. */
      fte7001_release_gpio (self);
      fpi_device_open_complete (dev,
        g_error_new (G_IO_ERROR, g_io_error_from_errno (errno),
                     "FTE7001: cannot open %s: %s", spidev_path,
                     g_strerror (errno)));
      return;
    }
  if (!fte7001_determine_spidev_speed (self, &error))
    {
      close (self->spi_fd);
      self->spi_fd = -1;
      fte7001_release_gpio (self);
      fpi_device_open_complete (dev, error);
      return;
    }

  /* Remember the working path for re-opens (see comment above). */
  g_free (self->spidev_cached);
  self->spidev_cached = g_strdup (spidev_path);

  /* Start init SSM: universal first probe (90 00 00 → A-CUT detect),
   * then branch warm/cold. */
  self->cold_path = FALSE;
  self->fe_round = 0;
  self->warm_retries = 0;
  self->chip_id = 0;
  {
    FpiSsm *ssm = fpi_ssm_new (dev, fte7001_init_handler, FTE7001_INIT_NSTATES);
    self->task_ssm = ssm;
    fpi_ssm_start (ssm, fte7001_init_complete);
    return;
  }
}

static void
fte7001_close (FpDevice *dev)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (dev);

  fte7001_release_gpio (self);
  if (self->spi_fd >= 0)
    {
      close (self->spi_fd);
      self->spi_fd = -1;
    }
  fpi_device_close_complete (dev, NULL);
}

/* ----- Action SSM (form B: shared capture pipeline for enroll/verify) ----- */
static void fte7001_capture_handler (FpiSsm *ssm, FpDevice *dev);
static void fte7001_capture_complete (FpiSsm *ssm, FpDevice *dev, GError *error);

enum fte7001_capture_state {
  FTE7001_CAPTURE_ARM_1F,
  FTE7001_CAPTURE_ARM_1F_DELAY,
  FTE7001_CAPTURE_ARM_1E,
  FTE7001_CAPTURE_ARM_SETTLE,
  FTE7001_CAPTURE_POLL_5B,
  FTE7001_CAPTURE_CHECK_5B,
  /* Soft wake pair (0x70 ×2, 6 ms apart) injected when the chip suspends
   * in the wait loop; then back to POLL_5B. */
  FTE7001_CAPTURE_SOFT_WAKE_1,
  /* Two-frame confirmation of the finger signal (kills ARM-adjacent
   * glitch false positives) + suspend watchdog lives in CHECK_5B. */
  FTE7001_CAPTURE_CONFIRM_FINGER_1,
  FTE7001_CAPTURE_CONFIRM_FINGER_2,
  FTE7001_CAPTURE_CONFIRM_FINGER_CHECK,
  FTE7001_CAPTURE_GATE_READ_30,
  FTE7001_CAPTURE_GATE_CHECK_30,
  /* Pre-capture 16B frame — the ONE legal 16B read position ("采图前一瞬",
   * production capture_once: 10 EF 1D 5B, then 16B, then 04FB).
   * Missing it corrupts the image RAM readout (form-B rewrite regression,
   * found by diffing tools/ft9338-calib-capture.py capture_once 2026-10-07). */
  FTE7001_CAPTURE_PRE_READ_5B,
  FTE7001_CAPTURE_PRE_READ_16B,
  FTE7001_CAPTURE_READ_IMAGE,
  FTE7001_CAPTURE_PROCESS_FRAME,
  FTE7001_CAPTURE_CLEANUP_READ_20,
  FTE7001_CAPTURE_CLEANUP_WRITE_54,
  FTE7001_CAPTURE_CLEANUP_READ_20B,
  /* Finger-off must be a real lift (form B design §三.4 / plan §三):
   * 5B poll until 2 consecutive frames with neither finger criterion,
   * 2 s cap, then report off. */
  FTE7001_CAPTURE_WAIT_OFF_POLL,
  FTE7001_CAPTURE_WAIT_OFF_CHECK,
  /* Quality-gate rejection: finger still down, wait for real lift then
   * re-capture the same stage. */
  FTE7001_CAPTURE_WAIT_OFF2_POLL,
  FTE7001_CAPTURE_WAIT_OFF2_CHECK,
  FTE7001_CAPTURE_REPORT_OFF,
  FTE7001_CAPTURE_DONE,
  FTE7001_CAPTURE_NSTATES,
};

static gboolean
fte7001_fail_if_cancelled (FpiSsm *ssm, FpDevice *dev)
{
  GCancellable *cancellable;
  GError *error = NULL;

  if (!fpi_device_action_is_cancelled (dev))
    return FALSE;

  cancellable = fpi_device_get_cancellable (dev);
  if (!cancellable ||
      !g_cancellable_set_error_if_cancelled (cancellable, &error))
    error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                 "Fingerprint operation was cancelled");
  fpi_ssm_mark_failed (ssm, error);
  return TRUE;
}

/* Finger-present criteria (Linux-verified 2026-10-07, dual-criterion OR). */
static gboolean
fte7001_finger_present (FpiDeviceFte7001 *self)
{
  return self->small_rx[4] == 0x01 || self->small_rx[4] == 0xa0 ||
         (self->small_rx[2] == 0x11 && self->small_rx[3] == 0x11);
}

/* WAIT_OFF 子循环共享：轮询 5B 直到真抬起（连续 2 帧双判据皆否）。
 * 参数 wait_start_us 为该轮等待的起点（2 s 兜底用）。 */
static void
fte7001_wait_off_submit (FpiSsm *ssm, gint64 wait_start_us)
{
  /* 2 s cap is evaluated by the caller (CHECK state) — submitting here
   * keeps the loop shape uniform (POLL → CHECK → POLL). */
  (void) wait_start_us;
  fte7001_submit_reg_read (ssm, FT9338_REG_FINGER_STATUS, 1, TRUE);
}

static void fte7001_clear_enroll_frames (FpiDeviceFte7001 *self);
static void fte7001_start_verify_match (FpiDeviceFte7001 *self);
static void fte7001_start_capture_ssm (FpiDeviceFte7001 *self, FpDevice *dev);

/* ----- Init SSM ----- */
static void
fte7001_init_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    /* --- Warm-probe preamble (Windows capture frames 1-11): 10EF20 + 70×4 + 10EF20/16/17 --- */
    case FTE7001_INIT_PREAMBLE_10EF20_1:
    case FTE7001_INIT_PREAMBLE_10EF20_2:
      fte7001_submit_reg_read (ssm, FT9338_REG_MCU_STATUS, 2, TRUE);
      return;
    case FTE7001_INIT_PREAMBLE_70_1:
    case FTE7001_INIT_PREAMBLE_70_2:
    case FTE7001_INIT_PREAMBLE_70_3:
    case FTE7001_INIT_PREAMBLE_70_4:
      {
        static const guint8 cmd70[1] = { 0x70 };
        fte7001_submit_write_only (ssm, cmd70, 1);
        return;
      }
    case FTE7001_INIT_PREAMBLE_10EF16:
      fte7001_submit_reg_read (ssm, FT9338_REG_CHIP_ID_HIGH, 1, TRUE);
      return;
    case FTE7001_INIT_PREAMBLE_10EF17:
      fte7001_submit_reg_read (ssm, FT9338_REG_CHIP_ID_LOW, 1, TRUE);
      return;

    /* --- Universal first probe: 90 00 00 → A-CUT detection (Windows cold-boot capture, 2026-10-06) --- */
    case FTE7001_INIT_ACUT_DETECT:
      fte7001_submit_acut_detect (ssm);
      return;
    case FTE7001_INIT_ACUT_CHECK:
      if (self->small_rx_valid && self->small_rx[2] == 0xef)
        {
          self->cold_path = TRUE;
          fp_dbg ("FT9338 A-CUT boot (EF) → cold path");
          fpi_ssm_jump_to_state (ssm, FTE7001_INIT_COLD_RESET_ASSERT);
          return;
        }
      fpi_ssm_jump_to_state (ssm, FTE7001_INIT_WARM_READ_MCU);
      return;

    /* --- Warm path: chip already alive → MCU idle check --- */
    case FTE7001_INIT_WARM_READ_MCU:
      fte7001_submit_reg_read (ssm, FT9338_REG_MCU_STATUS, 2, TRUE);
      return;
    case FTE7001_INIT_WARM_CHECK_MCU:
      if (fte7001_mcu_is_idle (self))
        {
          fp_dbg ("FT9338 warm path: MCU idle → skip cold");
          self->warm_retries = 0;
          fpi_ssm_jump_to_state (ssm, FTE7001_INIT_GATE_READ_30);
          return;
        }
      /* Single-frame non-idle is common while the chip is still in its
       * power-on transition (D-Bus activation timing is unpredictable).
       * Re-read a couple of times before paying the ~4 s cold sequence —
       * the cold path has A-CUT/second-reset fallbacks, so safety holds. */
      if (self->warm_retries < FT9338_WARM_RETRY_MAX)
        {
          self->warm_retries++;
          fp_dbg ("FT9338 warm path: MCU not idle, retry %u/%u",
                  self->warm_retries, FT9338_WARM_RETRY_MAX);
          fpi_ssm_jump_to_state_delayed (ssm, FTE7001_INIT_WARM_READ_MCU,
                                         FT9338_WARM_RETRY_DELAY_MS);
          return;
        }
      /* Not idle after retries → go cold */
      fpi_ssm_jump_to_state (ssm, FTE7001_INIT_COLD_RESET_ASSERT);
      return;

    /* --- Cold: GPIO reset 10 ms → deassert → settle 50 ms --- */
    case FTE7001_INIT_COLD_RESET_ASSERT:
      fte7001_set_hardware_reset (ssm, self, TRUE);
      return;
    case FTE7001_INIT_COLD_RESET_HOLD:
      fpi_ssm_next_state_delayed (ssm, FT9338_COLD_RESET_PULSE_MS);
      return;
    case FTE7001_INIT_COLD_RESET_DEASSERT:
      fte7001_set_hardware_reset (ssm, self, FALSE);
      return;
    case FTE7001_INIT_COLD_SETTLE:
      /* Windows sequence: deassert → immediately 55 AA, no settle delay. */
      fpi_ssm_jump_to_state (ssm, FTE7001_INIT_COLD_55AA);
      return;

    /* --- Cold: 55 AA (command mode) → 0xFE existence check loop --- */
    case FTE7001_INIT_COLD_55AA:
      {
        static const guint8 aa55[2] = { 0x55, 0xaa };
        fte7001_submit_write_only (ssm, aa55, 2);
        return;
      }
    case FTE7001_INIT_COLD_FE_CB_READ:
      fte7001_submit_short_read (ssm, FT9338_REG_CB, TRUE);
      return;
    case FTE7001_INIT_COLD_FE_CB_WRITE:
      fte7001_submit_short_write (ssm, FT9338_REG_CB, 0x20, TRUE);
      return;
    case FTE7001_INIT_COLD_FE_FD_WRITE:
      fte7001_submit_short_write (ssm, FT9338_REG_FD, 0x11, TRUE);
      return;
    case FTE7001_INIT_COLD_FE_FE_WRITE:
      fte7001_submit_short_write (ssm, FT9338_REG_FE, 0x11, TRUE);
      return;
    case FTE7001_INIT_COLD_FE_READ:
      fte7001_submit_short_read (ssm, FT9338_REG_FE, TRUE);
      return;
    case FTE7001_INIT_COLD_FE_CHECK:
      /* 08 F7 responses come in two flavours:
       *   Real data:  rx[1]==0x00 rx[2]==0x00 rx[3]==<value>
       *   Echo:       rx[1]==0x08 rx[2]==0xf7 rx[3]==<reg_byte>
       * Reference capture round 4 was echo 'aa 08 f7 fe' — rx[3]==0xfe was fake.
       * Discard echo before trusting FE != 0. */
      fp_dbg ("FT9338 FE raw: %02x %02x %02x %02x (round %u)",
              self->small_rx[0], self->small_rx[1],
              self->small_rx[2], self->small_rx[3], self->fe_round + 1);
      if (self->small_rx_valid
          && self->small_rx[1] == 0x08 && self->small_rx[2] == 0xf7)
        {
          fp_dbg ("FT9338 FE=0x%02x (echo, discard)", self->small_rx[3]);
          /* fall through to exhausted check below */
        }
      else if (self->small_rx_valid && self->small_rx[3] != 0)
        {
          fp_dbg ("FT9338 FE=0x%02x → chip has firmware, go warm",
                  self->small_rx[3]);
          fpi_ssm_jump_to_state (ssm, FTE7001_INIT_GATE_READ_30);
          return;
        }
      if (self->fe_round >= FT9338_FE_CHECK_ROUNDS - 1)
        {
          fp_dbg ("FT9338 FE exhausted (%u rounds) → download",
                  self->fe_round + 1);
          fpi_ssm_jump_to_state (ssm, FTE7001_INIT_COLD_D0_RESET_ASSERT);
          return;
        }
      fpi_ssm_jump_to_state (ssm, FTE7001_INIT_COLD_FE_DELAY);
      return;
    case FTE7001_INIT_COLD_FE_DELAY:
      /* Continue FE loop without GPIO reset.  The 01 §5 pseudo-code
       * reserves GPIO reset for step ② only (once, before 55 AA).
       * Do NOT reset per round — keeping command mode across rounds
       * is required for C2 identification to trigger. */
      fpi_ssm_jump_to_state_delayed (ssm, FTE7001_INIT_COLD_55AA,
                                     FT9338_FE_CHECK_DELAY_MS);
      self->fe_round++;
      return;

    /* --- Cold: D0Entry GPIO reset (Windows D5-to-D0 power transition, before 10EF20) --- */
    case FTE7001_INIT_COLD_D0_RESET_ASSERT:
      fte7001_set_hardware_reset (ssm, self, TRUE);
      return;
    case FTE7001_INIT_COLD_D0_RESET_HOLD:
      fpi_ssm_next_state_delayed (ssm, FT9338_COLD_RESET_PULSE_MS);
      return;
    case FTE7001_INIT_COLD_D0_RESET_DEASSERT:
      fte7001_set_hardware_reset (ssm, self, FALSE);
      return;

    /* --- Cold: 10 EF 20 read + 70 wr ×2 alternation ×3 (Windows capture frames 43-48) --- */
    case FTE7001_INIT_COLD_FW_10EF20_1:
    case FTE7001_INIT_COLD_FW_10EF20_2:
    case FTE7001_INIT_COLD_FW_10EF20_3:
      fte7001_submit_reg_read (ssm, FT9338_REG_MCU_STATUS, 2, TRUE);
      return;
    case FTE7001_INIT_COLD_FW_70a_1:
    case FTE7001_INIT_COLD_FW_70a_2:
    case FTE7001_INIT_COLD_FW_70b_1:
    case FTE7001_INIT_COLD_FW_70b_2:
      {
        static const guint8 cmd70[1] = { 0x70 };
        fte7001_submit_write_only (ssm, cmd70, 1);
        return;
      }

    /* --- Cold: 55 AA #6 firmware-branch entry (Windows capture frame 50) --- */
    case FTE7001_INIT_COLD_FW_55AA:
      {
        static const guint8 aa55[2] = { 0x55, 0xaa };
        fte7001_submit_write_only (ssm, aa55, 2);
        return;
      }

    /* --- Cold: C2 identification (0x02 → FT9338) --- */
    case FTE7001_INIT_COLD_C2_WRITE:
      fte7001_submit_short_write (ssm, FT9338_REG_C2, 0x55, TRUE);
      return;
    case FTE7001_INIT_COLD_C2_READ:
      fte7001_submit_short_read (ssm, FT9338_REG_C2, TRUE);
      return;
    case FTE7001_INIT_COLD_C2_CHECK:
      fp_dbg ("FT9338 C2 raw: %02x %02x %02x %02x",
              self->small_rx[0], self->small_rx[1],
              self->small_rx[2], self->small_rx[3]);
      /* Windows IC_EnterDownloadMode (0x1CE4) success criterion is
       * readback == written value (0x55): confirms command mode.  The
       * The Windows capture's "02 00 00 00" was stale small-frame buffer content,
       * not this chip's answer.  Linux verified: 00 00 00 55 on success. */
      if (!self->small_rx_valid || self->small_rx[3] != 0x55)
        {
          fpi_ssm_mark_failed (ssm,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
              "FT9338 C2 check failed: rx[3]=0x%02x (want 0x55)",
              self->small_rx_valid ? self->small_rx[3] : 0xff));
          return;
        }
      fp_dbg ("FT9338 C2=0x55 command mode confirmed");
      fpi_ssm_next_state (ssm);
      return;

    /* --- Cold: download mode --- */
    case FTE7001_INIT_COLD_DL_C8:
      fte7001_submit_short_write (ssm, FT9338_REG_C8, 0xff, TRUE);
      return;
    case FTE7001_INIT_COLD_DL_CA:
      fte7001_submit_short_write (ssm, FT9338_REG_CA, 0xff, TRUE);
      return;
    case FTE7001_INIT_COLD_DL_CB:
      fte7001_submit_short_write (ssm, FT9338_REG_CB, 0xff, TRUE);
      return;
    case FTE7001_INIT_COLD_DL_B9A:
      fte7001_submit_short_write (ssm, FT9338_REG_B9, 0xbf, TRUE);
      return;
    case FTE7001_INIT_COLD_DL_B9B:
      fte7001_submit_short_write (ssm, FT9338_REG_B9, 0xff, TRUE);
      return;

    /* --- Cold: firmware 05 FA block write (write-only) --- */
    case FTE7001_INIT_COLD_FW_WRITE:
      fp_dbg ("FT9338 downloading firmware (%u B) …", FT9338_FW_BLOB_SIZE);
      fte7001_submit_firmware_write (ssm);
      return;

    /* --- Cold: firmware 04 FB readback verify (full-duplex) --- */
    case FTE7001_INIT_COLD_FW_READBACK:
      fte7001_submit_firmware_readback (ssm);
      return;

    case FTE7001_INIT_COLD_FW_READBACK_CHECK:
    {
      gsize off;
      gboolean found = FALSE;

      /* The upper bound is derived from the remaining length, NOT a fixed
       * window: off must satisfy off + BLOB_SIZE <= READBACK_RX so the
       * full-length memcmp below can never run past the buffer end
       * (off <= 14144 - 14136 = 8; the old `off < 16` allowed a
       * 7-byte heap overread, fixed 2026-10-07). */
      for (off = 0; off + FT9338_FW_BLOB_SIZE <= FT9338_FW_READBACK_RX;
           off++)
        {
          if (memcmp (self->fw_readback_buf + off,
                      ft9338_firmware_blob, 64) == 0)
            {
              found = TRUE;
              break;
            }
        }
      if (!found ||
          memcmp (self->fw_readback_buf + off, ft9338_firmware_blob,
                  FT9338_FW_BLOB_SIZE) != 0)
        {
          /* Wipe either way: the buffer holds a full firmware copy. */
          memset (self->fw_readback_buf, 0, FT9338_FW_READBACK_RX);
          fpi_ssm_mark_failed (ssm,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
              "FT9338 firmware readback mismatch (firmware blob not found in readback buffer)"));
          return;
        }
      memset (self->fw_readback_buf, 0, FT9338_FW_READBACK_RX);
      fp_dbg ("FT9338 firmware readback verified (%u B @ offset %u)",
              FT9338_FW_BLOB_SIZE, (guint) off);
      fpi_ssm_next_state (ssm);
      return;
    }

    /* --- Cold: chip restart sequence (Windows 0x001665, chip_type==1) ---
     * Sleep(2) → rst(7ms) → Sleep(10) → rst(7ms) → Sleep(180).
     * The 04 FB readback leaves the chip in download mode; only this
     * double hard-reset makes the freshly written firmware execute. */
    case FTE7001_INIT_COLD_FW_RST2MS:
      fpi_ssm_next_state_delayed (ssm, 2);
      return;
    case FTE7001_INIT_COLD_FW_RST1_ASSERT:
      fte7001_set_hardware_reset (ssm, self, TRUE);
      return;
    case FTE7001_INIT_COLD_FW_RST1_HOLD:
      fpi_ssm_next_state_delayed (ssm, FT9338_FW_RESTART_PULSE_MS);
      return;
    case FTE7001_INIT_COLD_FW_RST1_DEASSERT:
      fte7001_set_hardware_reset (ssm, self, FALSE);
      return;
    case FTE7001_INIT_COLD_FW_RST10MS:
      fpi_ssm_next_state_delayed (ssm, 10);
      return;
    case FTE7001_INIT_COLD_FW_RST2_ASSERT:
      fte7001_set_hardware_reset (ssm, self, TRUE);
      return;
    case FTE7001_INIT_COLD_FW_RST2_HOLD:
      fpi_ssm_next_state_delayed (ssm, FT9338_FW_RESTART_PULSE_MS);
      return;
    case FTE7001_INIT_COLD_FW_RST2_DEASSERT:
      fte7001_set_hardware_reset (ssm, self, FALSE);
      return;
    case FTE7001_INIT_COLD_FW_RST180MS:
      /* chip_type==1 (FT9338): Sleep(180) before probing */
      fpi_ssm_next_state_delayed (ssm, FT9338_FW_BOOT_DELAY_MS);
      return;

    /* --- Cold: 10 EF 20 after firmware (Windows capture frame 60 — triggers download success) --- */
    case FTE7001_INIT_COLD_FW_10EF20:
      fte7001_submit_reg_read (ssm, FT9338_REG_MCU_STATUS, 2, TRUE);
      return;

    /* --- Cold: sensor ID sanity --- */
    case FTE7001_INIT_COLD_SENSOR_H:
      fte7001_submit_reg_read (ssm, FT9338_REG_SENSOR_ID_HIGH, 1, TRUE);
      return;
    case FTE7001_INIT_COLD_SENSOR_L:
    {
      guint8 id_high = fte7001_read_result_byte (self);

      if (!self->small_rx_valid || id_high != FT9338_SENSOR_ID_HIGH)
        {
          fpi_ssm_mark_failed (ssm,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
              "FT9338 sensor ID high mismatch: 0x%02x (expected 0x%02x)",
              self->small_rx_valid ? id_high : 0xff,
              FT9338_SENSOR_ID_HIGH));
          return;
        }
      fte7001_submit_reg_read (ssm, FT9338_REG_SENSOR_ID_LOW, 1, TRUE);
      return;
    }
    case FTE7001_INIT_COLD_SENSOR_CHECK:
    {
      guint8 id_low = fte7001_read_result_byte (self);

      if (!self->small_rx_valid || id_low != FT9338_SENSOR_ID_LOW)
        {
          fpi_ssm_mark_failed (ssm,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
              "FT9338 sensor ID low mismatch: 0x%02x (expected 0x%02x)",
              self->small_rx_valid ? id_low : 0xff,
              FT9338_SENSOR_ID_LOW));
          return;
        }
      fp_dbg ("FT9338 sensor ID verified: 0x%02x 0x%02x",
              FT9338_SENSOR_ID_HIGH, FT9338_SENSOR_ID_LOW);
      fpi_ssm_next_state (ssm);
      return;
    }
    case FTE7001_INIT_WRITE_01:
      fte7001_submit_reg_write (ssm, 0x01, 0x01, TRUE);
      return;
    case FTE7001_INIT_GATE_READ_30:
      fte7001_submit_reg_read (ssm, FT9338_REG_CONFIG_MARKER, 1, TRUE);
      return;
    case FTE7001_INIT_GATE_CHECK_30:
      if (fte7001_read_result_byte (self) == 0xbb)
        {
          /* Marker already set: rewriting config kills the finger-ready
           * status (2026-10-07).  Finish INIT here — the capture SSM
           * performs exactly the production ARM order (1F → 1E) in its
           * first states, which is all an armed chip needs. */
          fp_dbg ("FT9338 0x30 already 0xBB → skip config rewrite");
          fpi_ssm_jump_to_state (ssm, FTE7001_INIT_DONE);
          return;
        }
      fp_dbg ("FT9338 0x30=0x%02x → full config init",
              fte7001_read_result_byte (self));
      fpi_ssm_next_state (ssm);
      return;
    case FTE7001_INIT_DELAY_01:
    case FTE7001_INIT_DELAY_41:
    case FTE7001_INIT_DELAY_30:
    case FTE7001_INIT_DELAY_22:
    case FTE7001_INIT_DELAY_23:
      fpi_ssm_next_state_delayed (ssm, FT9338_CONFIG_DELAY_MS);
      return;
    case FTE7001_INIT_WRITE_41:
      fte7001_submit_reg_write (ssm, FT9338_REG_CONFIG_41, 0x0f, TRUE);
      return;
    case FTE7001_INIT_WRITE_30:
      fte7001_submit_reg_write (ssm, FT9338_REG_CONFIG_MARKER, 0xbb, TRUE);
      return;
    case FTE7001_INIT_VERIFY_30:
      fte7001_submit_reg_read (ssm, FT9338_REG_CONFIG_MARKER, 1, TRUE);
      return;
    case FTE7001_INIT_CHECK_30:
      if (fte7001_read_result_byte (self) != 0xbb)
        {
          fpi_ssm_mark_failed (ssm,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
              "FT9338 config marker verify failed (%02x)",
              fte7001_read_result_byte (self)));
          return;
        }
      fpi_ssm_next_state (ssm);
      return;
    case FTE7001_INIT_WRITE_22:
      fte7001_submit_reg_write (ssm, FT9338_REG_CONFIG_22, 0x00, TRUE);
      return;
    case FTE7001_INIT_WRITE_23:
      fte7001_submit_reg_write (ssm, FT9338_REG_CONFIG_23, 0x0e, TRUE);
      return;
    case FTE7001_INIT_FINAL_MCU:
      fte7001_submit_reg_read (ssm, FT9338_REG_MCU_STATUS, 2, TRUE);
      return;
    case FTE7001_INIT_CHECK_FINAL:
      if (!fte7001_mcu_is_idle (self))
        {
          fpi_ssm_mark_failed (ssm,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
              "FT9338 MCU not idle after config init (%02x %02x)",
              self->small_rx[4], self->small_rx[5]));
          return;
        }
      fpi_ssm_next_state (ssm);
      return;
    case FTE7001_INIT_DONE:
      fpi_ssm_mark_completed (ssm);
      return;
    case FTE7001_INIT_NSTATES:
      g_assert_not_reached ();
    }
}

static void
fte7001_init_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (dev);

  self->task_ssm = NULL;
  if (error)
    {
      /* Init failed: the framework will not call close after a
       * failed open, so undo open's claims here (fd + GPIO). */
      if (self->spi_fd >= 0)
        {
          close (self->spi_fd);
          self->spi_fd = -1;
        }
      fte7001_release_gpio (self);
      fpi_device_open_complete (dev, error);
      return;
    }
  fpi_device_open_complete (dev, NULL);
}

/* ----- Capture SSM ----- */
static void
fte7001_capture_handler (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (dev);
  guint8 finger_status;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FTE7001_CAPTURE_ARM_1F:
      if (fte7001_fail_if_cancelled (ssm, dev)) return;
      self->gate_rearm_count = 0;   /* per-stage budget (design §三) */
      self->image_handed_over = FALSE;   /* per-stage handover flag */
      fte7001_submit_reg_write (ssm, FT9338_REG_CAPTURE_ENABLE, 0x01, TRUE);
      return;
    case FTE7001_CAPTURE_ARM_1F_DELAY:
      fpi_ssm_next_state_delayed (ssm, FT9338_ARM_DELAY_MS);
      return;
    case FTE7001_CAPTURE_ARM_1E:
      fte7001_submit_reg_write (ssm, FT9338_REG_CAPTURE_START, 0x01, TRUE);
      return;
    case FTE7001_CAPTURE_ARM_SETTLE:
      fpi_ssm_next_state_delayed (ssm, FT9338_ARM_SETTLE_MS);
      return;

    case FTE7001_CAPTURE_POLL_5B:
      if (fte7001_fail_if_cancelled (ssm, dev)) return;
      if (g_get_monotonic_time () >= self->capture_deadline)
        {
          fpi_ssm_mark_failed (ssm,
            g_error_new_literal (G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
              "FT9338 timed out waiting for finger"));
          return;
        }
      /* 5B short frame — the ONLY frame allowed in the finger-wait loop
       * (Windows wire capture: 26/26 wait-phase reads are 5B; a 16B read
       * here kills the waiting MCU, verified 2026-10-07). */
      fte7001_submit_reg_read (ssm, FT9338_REG_FINGER_STATUS, 1, TRUE);
      return;
    case FTE7001_CAPTURE_CHECK_5B:
    {
      static const guint8 cmd70[1] = { 0x70 };

      finger_status = fte7001_finger_present (self);
      fp_dbg ("FT9338 0x1D 5B: %02x %02x %02x %02x %02x  ready=%d",
               self->small_rx[0], self->small_rx[1], self->small_rx[2],
               self->small_rx[3], self->small_rx[4], finger_status);
      if (finger_status)
        {
          /* Two-frame confirmation: re-read after 60 ms and require the
           * same verdict — kills ARM-adjacent glitch false positives
           * (production fp-unlock.py practice, verified 2026-10-07). */
          self->false_finger_count = 0;
          fpi_ssm_next_state (ssm);   /* → CONFIRM_FINGER */
          return;
        }
      /* Suspend watchdog: ~1.6 s after ARM with no touch the chip drops
       * to the all-zero suspend state that 0x1D polling cannot wake
       * (measured: 15 s / 284 frames still all-zero).  20 all-zero
       * frames ≈ 1 s → inject a 0x70 ×2 soft wake (write-only, the
       * production chain's wake idiom), then keep polling 5B. */
      if (self->small_rx_valid &&
          !fte7001_buf_has_data (self->small_rx, 5))
        self->false_finger_count++;
      else
        self->false_finger_count = 0;
      if (self->false_finger_count >= FT9338_SUSPEND_WAKE_FRAMES)
        {
          self->false_finger_count = 0;
          fp_dbg ("FT9338 wait loop: %u all-zero frames → 0x70 soft wake + re-ARM",
                  FT9338_SUSPEND_WAKE_FRAMES);
          fte7001_submit_write_only (ssm, cmd70, 1);
          return;
        }
      fpi_ssm_jump_to_state_delayed (ssm, FTE7001_CAPTURE_POLL_5B,
                                     FT9338_IRQ_FALLBACK_POLL_MS);
      return;
    }
    case FTE7001_CAPTURE_SOFT_WAKE_1:
    {
      /* Second 0x70 of the wake pair (production idiom is 0x70 ×2 with
       * a 6 ms gap).  After the wake the chip lost its ARM state —
       * returning to POLL_5B leaves a dead wait loop (2026-10-07 evening
       * run: 20 s of idle frames, 11 11 never came after suspend).
       * Re-ARM instead: the ARM sequence reopens the finger window
       * (matches calib/rearm_after_capture practice). */
      static const guint8 cmd70[1] = { 0x70 };
      fte7001_submit_write_only (ssm, cmd70, 1);
      return;
    }
    case FTE7001_CAPTURE_CONFIRM_FINGER_1:
      fpi_ssm_next_state_delayed (ssm, 60);
      return;
    case FTE7001_CAPTURE_CONFIRM_FINGER_2:
      fte7001_submit_reg_read (ssm, FT9338_REG_FINGER_STATUS, 1, TRUE);
      return;
    case FTE7001_CAPTURE_CONFIRM_FINGER_CHECK:
      if (fte7001_finger_present (self))
        {
          fpi_device_report_finger_status (dev, FP_FINGER_STATUS_PRESENT);
          fpi_ssm_jump_to_state (ssm, FTE7001_CAPTURE_GATE_READ_30);
          return;
        }
      /* Glitch / post-wake no-finger — re-ARM rather than polling: after
       * the suspend+wake cycle the ARM window is gone and 0x1D stays
       * idle forever (2026-10-07 evening run evidence).  ARM reopens it. */
      fpi_ssm_jump_to_state (ssm, FTE7001_CAPTURE_ARM_1F);
      return;

    case FTE7001_CAPTURE_GATE_READ_30:
      /* Critical 0x30 gate — must be read immediately before 04FB */
      fte7001_submit_reg_read (ssm, FT9338_REG_CONFIG_MARKER, 1, TRUE);
      return;
    case FTE7001_CAPTURE_GATE_CHECK_30:
      if (fte7001_read_result_byte (self) != 0xbb)
        {
          /* Marker lost while the finger was down.  Re-ARM with a budget
           * (plan §二.2): >3 re-ARMs in one stage means the marker is
           * really gone — fail the action instead of spinning forever. */
          if (++self->gate_rearm_count > 3)
            {
              fpi_ssm_mark_failed (ssm,
                fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                  "FT9338 config marker lost repeatedly before capture"));
              return;
            }
          fp_dbg ("FT9338 config marker lost before capture (%02x) → re-ARM %u/3",
                  fte7001_read_result_byte (self), self->gate_rearm_count);
          fpi_ssm_jump_to_state (ssm, FTE7001_CAPTURE_ARM_1F);
          return;
        }
      fpi_ssm_next_state (ssm);
      return;

    case FTE7001_CAPTURE_PRE_READ_5B:
      /* capture_once frame 1: 10 EF 1D 00 00 00 (5B data in 6B frame) */
      fte7001_submit_reg_read (ssm, FT9338_REG_FINGER_STATUS, 2, TRUE);
      return;
    case FTE7001_CAPTURE_PRE_READ_16B:
      /* capture_once frame 2: 10 EF 1D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 */
      fte7001_submit_reg_read (ssm, FT9338_REG_FINGER_STATUS, 12, TRUE);
      return;
    case FTE7001_CAPTURE_READ_IMAGE:
      fte7001_submit_capture (ssm);
      return;
    case FTE7001_CAPTURE_PROCESS_FRAME:
    {
      Fte7001Frame *frame = g_new (Fte7001Frame, 1);
      float cov, mtc;
      gboolean ok;

      /* Hand-over format: invert per byte, FPI_IMAGE_PARTIAL equivalent. */
      for (gsize i = 0; i < FT9338_IMAGE_SIZE; i++)
        frame->pixels[i] = (guint8) ~self->capture_rx[FT9338_CAPTURE_DATA_OFFSET + i];
      /* Secure-clear the raw SPI buffer */
      memset (self->capture_rx, 0, FT9338_CAPTURE_FRAME_SIZE);

      ok = fte7001_quality_check (frame, &cov, &mtc);
      fp_dbg ("FT9338 frame quality: cov=%.2f mtc=%.1f gate=%s",
              cov, mtc, ok ? "PASS" : "REJECT");

      if (!ok)
        {
          g_free (frame);
          if (self->quality_retries >= 3)
            {
              fpi_ssm_mark_failed (ssm,
                fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER));
              return;
            }
          self->quality_retries++;
          /* Finger probably still on the sensor — wait for a real lift,
           * then re-capture the same stage. */
          fpi_ssm_jump_to_state (ssm, FTE7001_CAPTURE_WAIT_OFF2_POLL);
          return;
        }

      self->quality_retries = 0;
      self->image_handed_over = TRUE;
      if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_ENROLL)
        {
          g_assert (self->enroll_stage < FT9338_ENROLL_STAGES);
          self->enroll_frames[self->enroll_stage] = frame;
          fpi_device_enroll_progress (dev, self->enroll_stage, NULL, NULL);
        }
      else
        {
          memcpy (&self->verify_probe, frame, sizeof (*frame));
          self->verify_probe_valid = TRUE;
          g_free (frame);
        }
      fpi_ssm_next_state (ssm);   /* → CLEANUP (ReturnAutoPower) */
      return;
    }

    case FTE7001_CAPTURE_CLEANUP_READ_20:
      /* ReturnAutoPower: 10 EF 20 → 11 EE 54 01 → 10 EF 20 */
      fte7001_submit_reg_read (ssm, FT9338_REG_MCU_STATUS, 1, TRUE);
      return;
    case FTE7001_CAPTURE_CLEANUP_WRITE_54:
      fte7001_submit_reg_write (ssm, FT9338_REG_QUICK_TRIGGER, 0x01, TRUE);
      return;
    case FTE7001_CAPTURE_CLEANUP_READ_20B:
      fte7001_submit_reg_read (ssm, FT9338_REG_MCU_STATUS, 2, TRUE);
      return;

    case FTE7001_CAPTURE_WAIT_OFF_POLL:
      if (fte7001_fail_if_cancelled (ssm, dev)) return;
      /* Sentinel: wait_off_start == 0 means "round not started" — set it
       * ONCE per round, otherwise the 2 s cap in wait_off_submit can
       * never fire (each poll would reset the origin). */
      if (self->wait_off_start == 0)
        self->wait_off_start = g_get_monotonic_time ();
      fte7001_wait_off_submit (ssm, self->wait_off_start);
      return;
    case FTE7001_CAPTURE_WAIT_OFF_CHECK:
      if (self->wait_off_start > 0 &&
          g_get_monotonic_time () - self->wait_off_start > 2 * G_TIME_SPAN_SECOND)
        {
          /* 2 s cap — treat as lifted (user will not hold forever). */
          self->wait_off_lift_count = 0;
          self->wait_off_start = 0;
          fpi_ssm_jump_to_state (ssm, FTE7001_CAPTURE_REPORT_OFF);
          return;
        }
      if (fte7001_finger_present (self))
        self->wait_off_lift_count = 0;
      else if (self->small_rx_valid)
        self->wait_off_lift_count++;
      if (self->wait_off_lift_count >= 2)
        {
          self->wait_off_lift_count = 0;
          self->wait_off_start = 0;
          /* WAIT_OFF2_POLL sits between CHECK and REPORT_OFF in the enum:
           * next_state would land in the quality-retry loop! */
          fpi_ssm_jump_to_state (ssm, FTE7001_CAPTURE_REPORT_OFF);
          return;
        }
      fpi_ssm_jump_to_state_delayed (ssm, FTE7001_CAPTURE_WAIT_OFF_POLL,
                                     FT9338_IRQ_FALLBACK_POLL_MS);
      return;

    case FTE7001_CAPTURE_WAIT_OFF2_POLL:
      if (fte7001_fail_if_cancelled (ssm, dev)) return;
      if (self->wait_off_start == 0)
        self->wait_off_start = g_get_monotonic_time ();
      fte7001_wait_off_submit (ssm, self->wait_off_start);
      return;
    case FTE7001_CAPTURE_WAIT_OFF2_CHECK:
      if (self->wait_off_start > 0 &&
          g_get_monotonic_time () - self->wait_off_start > 2 * G_TIME_SPAN_SECOND)
        {
          self->wait_off_lift_count = 0;
          self->wait_off_start = 0;
          self->capture_deadline =
            g_get_monotonic_time () + (gint64) FT9338_FINGER_TIMEOUT_MS * 1000;
          fpi_ssm_jump_to_state (ssm, FTE7001_CAPTURE_POLL_5B);
          return;
        }
      if (fte7001_finger_present (self))
        self->wait_off_lift_count = 0;
      else if (self->small_rx_valid)
        self->wait_off_lift_count++;
      if (self->wait_off_lift_count >= 2)
        {
          /* Real lift after a quality rejection — same stage, fresh
           * finger press. */
          self->wait_off_lift_count = 0;
          self->wait_off_start = 0;
          self->capture_deadline =
            g_get_monotonic_time () + (gint64) FT9338_FINGER_TIMEOUT_MS * 1000;
          fpi_ssm_jump_to_state (ssm, FTE7001_CAPTURE_POLL_5B);
          return;
        }
      fpi_ssm_jump_to_state_delayed (ssm, FTE7001_CAPTURE_WAIT_OFF2_POLL,
                                     FT9338_IRQ_FALLBACK_POLL_MS);
      return;

    case FTE7001_CAPTURE_REPORT_OFF:
      self->wait_off_start = 0;   /* leave the wait loop (timeout exit too) */
      fpi_device_report_finger_status (dev, FP_FINGER_STATUS_NONE);
      /* ENROLL → next stage or finish; VERIFY → SSM completes and the
       * complete callback dispatches the matcher.  No per-action fork
       * beyond this point (form B deletes CLEANUP_LOOP — the 2026-10-07
       * crash layer). */
      if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_ENROLL)
        {
          if (fte7001_fail_if_cancelled (ssm, dev)) return;
          self->enroll_stage++;
          if (self->enroll_stage < FT9338_ENROLL_STAGES)
            {
              self->capture_deadline =
                g_get_monotonic_time () + (gint64) FT9338_FINGER_TIMEOUT_MS * 1000;
              fpi_ssm_jump_to_state (ssm, FTE7001_CAPTURE_ARM_1F);
              return;
            }
          /* All stages captured — SSM completes; template assembly and
           * enroll_complete happen in the complete callback (single
           * exit rule). */
        }
      fpi_ssm_next_state (ssm);   /* → DONE */
      return;

    case FTE7001_CAPTURE_DONE:
      fpi_ssm_mark_completed (ssm);
      return;
    case FTE7001_CAPTURE_NSTATES:
      g_assert_not_reached ();
    }
}

static void
fte7001_capture_complete (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (dev);

  self->task_ssm = NULL;

  /* Complete-callback is the ONLY exit for *_complete calls (design
   * invariant).  Error mapping happens here, by kind. */
  if (error && self->image_handed_over &&
      !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
    {
      /* Frame already consumed; a cleanup failure must not kill the
       * action (plan §二.3 form-B equivalent).  The captured frame is
       * safe in enroll_frames[] / verify_probe — resume the action as
       * if the capture loop had finished normally. */
      fp_dbg ("FT9338 cleanup after frame handover failed (ignored): %s",
              error->message);
      g_error_free (error);
      error = NULL;

      if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_ENROLL)
        {
          self->enroll_stage++;
          if (self->enroll_stage < FT9338_ENROLL_STAGES)
            {
              fte7001_start_capture_ssm (self, dev);
              return;
            }
          /* fall through: all stages done — assemble template below */
        }
      else if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
        {
          if (self->verify_probe_valid)
            {
              fte7001_start_verify_match (self);
              return;
            }
          /* no probe (handover flag set but SSM died before READ_IMAGE?
           * cannot happen; guard anyway) */
          fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL,
            fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
              "FT9338 verify lost probe after cleanup failure"));
          fpi_device_verify_complete (dev, NULL);
          return;
        }
      else
        return;
    }

  /* (No switch: -Wswitch-enum with the full FpiDeviceAction list.) */
  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_ENROLL)
    {
      if (!error && self->enroll_stage >= FT9338_ENROLL_STAGES)
        {
          /* All stages captured — assemble the wire template into the
           * FpPrint from fpi_device_get_enroll_data. */
          GVariant *data;
          gsize wire_len = 14 + (gsize) FT9338_ENROLL_STAGES * FT9338_IMAGE_SIZE;
          guint8 *wire = g_malloc (wire_len);
          guint i;

          wire[0] = 'F'; wire[1] = 'T'; wire[2] = '9'; wire[3] = '3';
          wire[4] = 1;    /* version */
          wire[5] = FT9338_ENROLL_STAGES;
          wire[6] = 0; wire[7] = FT9338_IMAGE_WIDTH;    /* big-endian */
          wire[8] = 0; wire[9] = FT9338_IMAGE_HEIGHT;
          wire[10] = (guint8) (((guint32) (FT9338_ENROLL_STAGES * FT9338_IMAGE_SIZE)) >> 24) & 0xff;
          wire[11] = (guint8) (((guint32) (FT9338_ENROLL_STAGES * FT9338_IMAGE_SIZE)) >> 16) & 0xff;
          wire[12] = (guint8) (((guint32) (FT9338_ENROLL_STAGES * FT9338_IMAGE_SIZE)) >> 8) & 0xff;
          wire[13] = (guint8) ((guint32) (FT9338_ENROLL_STAGES * FT9338_IMAGE_SIZE)) & 0xff;
          for (i = 0; i < FT9338_ENROLL_STAGES; i++)
            memcpy (wire + 14 + (gsize) i * FT9338_IMAGE_SIZE,
                    self->enroll_frames[i]->pixels, FT9338_IMAGE_SIZE);

          /* element type BYTE (fte3600.c:439 pattern) — passing
           * G_VARIANT_TYPE ("ay") here creates "aay" (non-fixed-size),
           * which crashes fp_print_serialize (2026-10-07 run evidence). */
          data = g_variant_ref_sink (
            g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, wire, wire_len, 1));
          g_assert (g_variant_is_of_type (data, G_VARIANT_TYPE ("ay")));
          fpi_print_set_type (self->enroll_print, FPI_PRINT_RAW);
          g_object_set (self->enroll_print, "fpi-data", data, NULL);
          g_variant_unref (data);
          g_free (wire);

          fpi_device_enroll_complete (dev, g_object_ref (self->enroll_print), NULL);
          fte7001_clear_enroll_frames (self);
          g_clear_object (&self->enroll_print);
          return;
        }
      /* Failure/timeout path */
      {
        GError *e = error;
        if (e && g_error_matches (e, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
          e = fpi_device_retry_new (FP_DEVICE_RETRY_TOO_SHORT);
        if (e && e->domain == FP_DEVICE_RETRY)
          {
            /* Retryable (finger-wait timeout / quality cap): report the
             * stage with the retry error so the UI can prompt, then
             * restart the capture SSM — form B has no framework-side
             * re-arm loop (fte3600 restarts its scan the same way). */
            fpi_device_enroll_progress (dev, self->enroll_stage, NULL, e);
            if (error) g_error_free (error);
            fte7001_start_capture_ssm (self, dev);
            return;
          }
        fpi_device_enroll_complete (dev, NULL, e ? e : error);
        if (e != error) g_error_free (e);
        return;
      }
  }
  else if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    {
      if (error)
        {
          if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
            {
              /* Framework contract: a verify action must always have a
               * reported result before complete — bare complete(NULL)
               * triggers "did not report the result earlier" and the
               * action is turned into verify-no-match (journal proof,
               * 2026-10-07 22:38:11). */
              fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL,
                                         g_error_copy (error));
              fpi_device_verify_complete (dev, NULL);
              return;
            }
          if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
            {
              fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL,
                fpi_device_retry_new (FP_DEVICE_RETRY_TOO_SHORT));
              fpi_device_verify_complete (dev, NULL);
              return;
            }
          if (error->domain == FP_DEVICE_RETRY)
            {
              fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL,
                                        g_error_copy (error));
              fpi_device_verify_complete (dev, NULL);
              return;
            }
          fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL,
                                    g_error_copy (error));
          fpi_device_verify_complete (dev, NULL);
          return;
        }
      /* Happy path: probe captured — dispatch the matcher worker. */
      fte7001_start_verify_match (self);
      return;
    }
  else
    {
      /* FPI_DEVICE_ACTION_NONE and everything else */
      if (error)
        g_error_free (error);
    }
}

/* ----- Template wire helpers (design §五) ----- */

static void
fte7001_clear_enroll_frames (FpiDeviceFte7001 *self)
{
  guint i;
  for (i = 0; i < FT9338_ENROLL_STAGES; i++)
    g_clear_pointer (&self->enroll_frames[i], g_free);
}

/* Decode the "FT93" wire template (all multi-byte header fields
 * big-endian).  Returns a freshly allocated array of *n_frames frames,
 * or NULL with a caller-friendly GError. */
static Fte7001Frame *
fte7001_template_decode (const guint8 *wire, gsize wire_size,
                         guint *n_frames, GError **error)
{
  Fte7001Frame *frames;
  guint count, i;
  guint32 payload_len;

  if (wire_size < 14 ||
      wire[0] != 'F' || wire[1] != 'T' || wire[2] != '9' || wire[3] != '3')
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "FTE7001 template magic mismatch");
      return NULL;
    }
  if (wire[4] != 1)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED,
                   "FTE7001 template version %u unsupported", wire[4]);
      return NULL;
    }
  count = wire[5];
  if (count < 1 || count > 16)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "FTE7001 template frame count %u invalid", count);
      return NULL;
    }
  /* width/height big-endian (design §五: 全头统一大端) */
  if ((wire[6] << 8 | wire[7]) != FT9338_IMAGE_WIDTH ||
      (wire[8] << 8 | wire[9]) != FT9338_IMAGE_HEIGHT)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "FTE7001 template geometry mismatch");
      return NULL;
    }
  payload_len = ((guint32) wire[10] << 24) | ((guint32) wire[11] << 16) |
                ((guint32) wire[12] << 8) | (guint32) wire[13];
  if (payload_len != (guint32) count * FT9338_IMAGE_SIZE ||
      14 + (gsize) payload_len != wire_size)
    {
      g_set_error (error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID,
                   "FTE7001 template length check failed");
      return NULL;
    }

  frames = g_new (Fte7001Frame, count);
  for (i = 0; i < count; i++)
    memcpy (frames[i].pixels, wire + 14 + (gsize) i * FT9338_IMAGE_SIZE,
            FT9338_IMAGE_SIZE);
  *n_frames = count;
  return frames;
}

/* ----- Verify matcher worker (GTask, fte3600 pattern) ----- */

typedef struct {
  Fte7001Frame *template_frames;   /* owned copy */
  guint n_template_frames;
  Fte7001Frame probe;               /* owned copy */
} Fte7001VerifyJob;

static void
fte7001_verify_job_free (gpointer p)
{
  Fte7001VerifyJob *job = p;
  g_free (job->template_frames);
  g_free (job);
}

static void
fte7001_verify_match_worker (GTask *task, gpointer source, gpointer task_data,
                             GCancellable *cancellable)
{
  Fte7001VerifyJob *job = task_data;
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (source);
  Fte7001FeatureSet probe_fs;
  float best = 0.0f;
  float scores[32];             /* per-template-frame score trail */
  guint n_scores = 0;
  guint i;

  (void) self;

  if (g_task_return_error_if_cancelled (task))
    return;

  /* Descriptors are computed fresh from the raw frames here (design §四:
   * no cross-action caching; worker owns its data only).  Known future
   * optimization: precompute template descriptors at template-decode time
   * and carry them in the job (saves 9/9 recomputes per verify) —
   * deliberately NOT done during the observation period to avoid
   * introducing new variables while thresholds are being tuned. */
  probe_fs = fte7001_feature_extract (&job->probe);
  if (probe_fs.n_feats > 0)
    {
      for (i = 0; i < job->n_template_frames; i++)
        {
          Fte7001FeatureSet tfs;

          if (g_cancellable_is_cancelled (cancellable))
            {
              /* Abort mid-loop: free what we hold and return an error so
               * the GTask completes (a bare return would leak the task
               * into "never completes" and hang the action). */
              fte7001_feature_set_free (&probe_fs);
              g_task_return_new_error (task, G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                       "FTE7001 verify match was cancelled");
              return;
            }

          tfs = fte7001_feature_extract (&job->template_frames[i]);
          {
            float s = 0.0f;

            if (tfs.n_feats >= FT9338_M_MIN_FEATS)
              s = fte7001_match_score (&tfs, &probe_fs);
            if (s > best)
              best = s;
            if (n_scores < G_N_ELEMENTS (scores))
              scores[n_scores++] = s;
          }
          fte7001_feature_set_free (&tfs);
        }
    }
  fte7001_feature_set_free (&probe_fs);

  /* Per-frame score trail in the journal: keeps the raw distribution so
   * threshold tuning and "top-2 instead of max" experiments can be
   * re-evaluated offline from logs alone (no re-enrollment needed). */
  if (n_scores > 0)
    {
      GString *gs = g_string_new ("FT9338 verify per-frame scores:");
      float top1 = 0.0f, top2 = 0.0f;

      for (i = 0; i < n_scores; i++)
        {
          g_string_append_printf (gs, " %.1f", scores[i]);
          if (scores[i] > top1)
            { top2 = top1; top1 = scores[i]; }
          else if (scores[i] > top2)
            top2 = scores[i];
        }
      g_string_append_printf (gs, "  top2=(%.1f, %.1f)", top1, top2);
      fp_dbg ("%s", gs->str);
      g_string_free (gs, TRUE);
    }

  g_task_return_int (task, (gssize) roundf (best * 100.0f));
}

static void
fte7001_verify_match_done (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (source);
  FpDevice *dev = FP_DEVICE (self);
  gssize raw;
  float score;
  gboolean match;

  (void) user_data;

  if (g_task_had_error (G_TASK (result)))
    {
      /* Cancelled mid-match.  On cancel the framework calls fte7001_cancel
       * and the SSM exits through its own complete callback which has
       * ALREADY run verify_complete for the cancellation — completing
       * again here would double-complete the action.  Only complete if
       * the verify action is somehow still pending (SSM already gone). */
      if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_complete (dev, NULL);
      return;
    }

  raw = g_task_propagate_int (G_TASK (result), NULL);
  score = (float) raw / 100.0f;
  match = score >= FT9338_MATCH_THRESHOLD;
  fp_dbg ("FT9338 verify score %.1f (threshold %.1f) → %s",
          score, FT9338_MATCH_THRESHOLD, match ? "MATCH" : "no-match");
  fpi_device_verify_report (dev, match ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                            NULL, NULL);
  fpi_device_verify_complete (dev, NULL);
}

static void
fte7001_start_verify_match (FpiDeviceFte7001 *self)
{
  FpDevice *dev = FP_DEVICE (self);
  FpPrint *print = NULL;
  g_autoptr(GVariant) data = NULL;
  const guint8 *wire;
  gsize wire_size = 0;
  GError *error = NULL;
  Fte7001Frame *frames;
  guint n_frames;
  Fte7001VerifyJob *job;
  GTask *task;

  fpi_device_get_verify_data (dev, &print);
  if (print == NULL || !fp_print_compatible (print, dev) ||
      fpi_print_get_type (print) != FPI_PRINT_RAW)
    {
      fpi_device_verify_complete (dev, fpi_device_error_new_msg (
        FP_DEVICE_ERROR_DATA_INVALID,
        "FTE7001 verification requires a compatible raw template"));
      return;
    }
  g_object_get (print, "fpi-data", &data, NULL);
  if (data == NULL || !g_variant_is_of_type (data, G_VARIANT_TYPE ("ay")) ||
      !g_variant_is_normal_form (data))
    {
      fpi_device_verify_complete (dev, fpi_device_error_new_msg (
        FP_DEVICE_ERROR_DATA_INVALID,
        "FTE7001 verification template has an invalid container"));
      return;
    }
  wire = g_variant_get_fixed_array (data, &wire_size, 1);
  frames = fte7001_template_decode (wire, wire_size, &n_frames, &error);
  if (frames == NULL)
    {
      fpi_device_verify_complete (dev, error);
      return;
    }

  job = g_new0 (Fte7001VerifyJob, 1);
  job->template_frames = frames;
  job->n_template_frames = n_frames;
  job->probe = self->verify_probe;   /* struct copy */
  self->verify_probe_valid = FALSE;

  self->worker_cancellable = g_cancellable_new ();
  task = g_task_new (dev, self->worker_cancellable,
                     fte7001_verify_match_done, NULL);
  g_task_set_task_data (task, job, fte7001_verify_job_free);
  g_task_set_return_on_cancel (task, FALSE);
  g_task_run_in_thread (task, fte7001_verify_match_worker);
  g_object_unref (task);
}

/* ----- Action entry points (form B) ----- */

static void
fte7001_start_capture_ssm (FpiDeviceFte7001 *self, FpDevice *dev)
{
  FpiSsm *ssm;

  self->image_handed_over = FALSE;
  self->quality_retries = 0;
  self->capture_deadline =
    g_get_monotonic_time () + (gint64) FT9338_FINGER_TIMEOUT_MS * 1000;
  ssm = fpi_ssm_new (dev, fte7001_capture_handler, FTE7001_CAPTURE_NSTATES);
  self->task_ssm = ssm;
  fpi_ssm_start (ssm, fte7001_capture_complete);
}

static void
fte7001_enroll (FpDevice *dev)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (dev);
  FpPrint *print = NULL;

  fte7001_clear_enroll_frames (self);
  self->enroll_stage = 0;
  fpi_device_get_enroll_data (dev, &print);
  /* fpi_device_get_enroll_data returns a borrowed reference — take our
   * own for self->enroll_print (released in finalize / after complete). */
  g_set_object (&self->enroll_print, print);
  fte7001_start_capture_ssm (self, dev);
}

static void
fte7001_verify (FpDevice *dev)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (dev);

  self->verify_probe_valid = FALSE;
  fte7001_start_capture_ssm (self, dev);
}

static void
fte7001_cancel (FpDevice *dev)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (dev);

  /* Kill the matcher worker only.  The action cancellable belongs to
   * the framework — cancelling it from the driver turns successful
   * actions into G_IO_ERROR_CANCELLED (the 2026-10-07 killer; the
   * same rule as the old deactivate).  The SSM exits through
   * fte7001_fail_if_cancelled at the next state entry. */
  if (self->worker_cancellable)
    g_cancellable_cancel (self->worker_cancellable);
}

/* ----- Class init ----- */
static void
fpi_device_fte7001_init (FpiDeviceFte7001 *self)
{
  self->spi_fd = -1;
  self->capture_tx = g_malloc0 (FT9338_CAPTURE_FRAME_SIZE);
  self->capture_rx = g_malloc0 (FT9338_CAPTURE_FRAME_SIZE);

  /* 04 FB 34 00 1E 48 00 — address 0x3400, length 0x1E48 = 7752 */
  self->capture_tx[0] = 0x04;
  self->capture_tx[1] = 0xfb;
  self->capture_tx[2] = 0x34;  /* addr high */
  self->capture_tx[3] = 0x00;  /* addr low  */
  self->capture_tx[4] = 0x1e;  /* len high  */
  self->capture_tx[5] = 0x48;  /* len low   */

  /* Firmware write buffer: 6 (header) + blob + 1 (tail 0x00) */
  self->fw_write_buf = g_malloc0 (6 + FT9338_FW_BLOB_SIZE + 1);
  self->fw_write_buf[0] = 0x05;       /* 05 FA */
  self->fw_write_buf[1] = 0xFA;
  self->fw_write_buf[2] = FT9338_FW_ADDR_HIGH;
  self->fw_write_buf[3] = FT9338_FW_ADDR_LOW;
  self->fw_write_buf[4] = 0x37;       /* len hi: 0x3738 = 14136 */
  self->fw_write_buf[5] = 0x38;       /* len lo */
  memcpy (self->fw_write_buf + 6, ft9338_firmware_blob, FT9338_FW_BLOB_SIZE);
  self->fw_write_buf[6 + FT9338_FW_BLOB_SIZE] = 0x00;  /* tail */

  /* Firmware readback RX buffer */
  self->fw_readback_buf = g_malloc0 (FT9338_FW_READBACK_RX);
}

static void
fpi_device_fte7001_finalize (GObject *object)
{
  FpiDeviceFte7001 *self = FPI_DEVICE_FTE7001 (object);

  if (self->spi_fd >= 0) close (self->spi_fd);
  self->spi_fd = -1;
  fte7001_release_gpio (self);
  g_free (self->capture_tx);
  g_free (self->capture_rx);
  g_free (self->fw_write_buf);
  g_free (self->fw_readback_buf);
  fte7001_clear_enroll_frames (self);
  g_clear_object (&self->enroll_print);
  g_clear_pointer (&self->spidev_cached, g_free);
  g_clear_object (&self->worker_cancellable);

  G_OBJECT_CLASS (fpi_device_fte7001_parent_class)->finalize (object);
}

static void
fpi_device_fte7001_class_init (FpiDeviceFte7001Class *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  dev_class->id       = "fte7001";
  dev_class->full_name = "FocalTech FT9338 Embedded Fingerprint Sensor";
  dev_class->type     = FP_DEVICE_TYPE_UDEV;
  dev_class->id_table = fte7001_id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->temp_hot_seconds = -1;
  dev_class->nr_enroll_stages = FT9338_ENROLL_STAGES;   /* 9 (2026-10-07 定稿) */

  dev_class->probe   = NULL;  /* using id_table spidev match */
  dev_class->open    = fte7001_open;
  dev_class->close   = fte7001_close;
  dev_class->enroll  = fte7001_enroll;
  dev_class->verify  = fte7001_verify;
  dev_class->cancel  = fte7001_cancel;
  /* identify not implemented: single-user lock-screen only needs verify
   * (fte3600 leaves it NULL for the same reason). */

  G_OBJECT_CLASS (klass)->finalize = fpi_device_fte7001_finalize;
  fpi_device_class_auto_initialize_features (dev_class);
}