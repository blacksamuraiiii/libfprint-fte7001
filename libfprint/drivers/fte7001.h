/*
 * FocalTech FTE7001 / FT9338 SPI fingerprint driver
 *
 * Based on fte3600.c (FT9361).  The FT9338 is a RAM-loaded-firmware device
 * from the same FocalTech 93xx family.  Key differences from FT9361:
 *   - Firmware is downloaded to RAM on cold boot (05 FA 14136 B + 04 FB
 *     verify + double reset, 2026-10-06); S5 power loss clears it
 *   - No 0x76 CAPTURE_MODE register
 *   - 0x30 gate: read 0x30 (verify 0xBB) immediately before 04FB capture
 *   - Image: 88 x 88 = 7744 B (vs. 64 x 80 = 5120 B)
 *   - Capture frame: 7752 B, data offset 8 (vs. 5128 B)
 *   - Sensor ID: 0x58 / 0x58 (vs. 0x40 / 0x50)
 *   - GPIO 86 never fires; finger detection polls 0x1D
 *
 * Copyright (C) 2026 FTE7001 Linux contributors
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <config.h>

#ifndef HAVE_UDEV
#error "fte7001 requires udev"
#endif

#ifndef HAVE_GPIOD
#error "fte7001 requires libgpiod"
#endif

#include <fp-device.h>
#include <fpi-device.h>

#define FTE7001_SPI_SPEED_HZ 1000000U

#define FT9338_IMAGE_WIDTH   88
#define FT9338_IMAGE_HEIGHT  88
#define FT9338_IMAGE_SIZE    (FT9338_IMAGE_WIDTH * FT9338_IMAGE_HEIGHT)  /* 7744 */
#define FT9338_CAPTURE_FRAME_SIZE   (FT9338_IMAGE_SIZE + 8)              /* 7752 */
#define FT9338_CAPTURE_DATA_OFFSET  8
#define FT9338_CAPTURE_CMD_SIZE     7

#define FT9338_SENSOR_ID_HIGH  0x58
#define FT9338_SENSOR_ID_LOW   0x58
#define FT9338_FW_VERSION      0x3D
#define FT9338_AGC_VERSION     0x10

#define FT9338_IMAGE_ADDR_HIGH 0x34
#define FT9338_IMAGE_ADDR_LOW  0x00

#define FT9338_IMAGE_PPMM      20.0  /* 508 DPI */

#define FT9338_IRQ_FALLBACK_POLL_MS  50
/* Form B (2026-10-07): 9 frames per finger — leave-one-out verified
 * (true-finger min 13.1 vs threshold 7.0); 7 works, 5 does not
 * (margin +0.8).  See feat/模板帧数分布曲线-20261007.txt. */
#define FT9338_ENROLL_STAGES 9
/* --- Timing constants (ms) --- */
#define FT9338_RESET_PULSE_MS     20      /* warm/reset fallback */
#define FT9338_RESET_DELAY_MS      6
#define FT9338_RESET_SETTLE_MS     5
#define FT9338_CONFIG_DELAY_MS     2
#define FT9338_ARM_DELAY_MS        2
#define FT9338_ARM_SETTLE_MS      10
#define FT9338_POLL_DELAY_MS      50
#define FT9338_FINGER_TIMEOUT_MS  20000

/* Cold-boot timing (Windows cold-boot capture verified 2026-10-06) */
#define FT9338_COLD_RESET_PULSE_MS   10   /* GPIO low pulse */
#define FT9338_COLD_RESET_SETTLE_MS  50   /* after deassert */
#define FT9338_FE_CHECK_ROUNDS        5   /* 0xFE existence check */
#define FT9338_FE_CHECK_DELAY_MS     10   /* between rounds */
#define FT9338_WARM_RETRY_MAX         2   /* MCU idle re-reads before cold path */
#define FT9338_WARM_RETRY_DELAY_MS  150   /* between warm re-reads */
#define FT9338_SUSPEND_WAKE_FRAMES   20   /* all-zero 5B frames (~1 s) before 0x70 soft wake */

typedef struct
{
  const gchar *sys_vendor;
  const gchar *product_name;
  const gchar *controller_acpi_path;
  const gchar *controller_hid;
  guint        reset_offset;
  guint        irq_offset;
} Fte7001GpioProfile;

const Fte7001GpioProfile *fpi_fte7001_lookup_gpio_profile (const gchar *sys_vendor,
                                                           const gchar *product_name);

/* --- Register definitions --- */
#define FT9338_REG_SENSOR_ID_HIGH  0x14
#define FT9338_REG_SENSOR_ID_LOW   0x15
#define FT9338_REG_CHIP_ID_HIGH    0x16  /* reads back 0x93 */
#define FT9338_REG_CHIP_ID_LOW     0x17  /* reads back 0x38 */
#define FT9338_CHIP_ID             0x9338
#define FT9338_REG_FW_VERSION      0x1A
#define FT9338_REG_AGC_VERSION     0x3C
#define FT9338_REG_FINGER_STATUS   0x1D
#define FT9338_REG_CAPTURE_START   0x1E
#define FT9338_REG_CAPTURE_ENABLE  0x1F
#define FT9338_REG_MCU_STATUS      0x20
#define FT9338_REG_CONFIG_22       0x22
#define FT9338_REG_CONFIG_23       0x23
#define FT9338_REG_CONFIG_MARKER   0x30
#define FT9338_REG_CONFIG_41       0x41
#define FT9338_REG_QUICK_TRIGGER   0x54

#define FT9338_REG_READ_HEADER_SIZE  4
#define FT9338_REG_WRITE_SIZE        5
#define FT9338_SMALL_FRAME_SIZE      20

/* Cold-boot register addresses (08F7 / 09F6 short-config domain) */
#define FT9338_REG_CB             0xCB
#define FT9338_REG_C2             0xC2
#define FT9338_REG_C8             0xC8
#define FT9338_REG_CA             0xCA
#define FT9338_REG_B9             0xB9
#define FT9338_REG_FD             0xFD
#define FT9338_REG_FE             0xFE

/* Firmware download constants (Windows cold-boot capture verified 2026-10-06) */
#define FT9338_FW_BLOB_SIZE        14136   /* 0x3738 */
#define FT9338_FW_READBACK_RX      14144   /* blob + 6-byte SPI receipt header */
#define FT9338_FW_ADDR_HIGH        0x00
#define FT9338_FW_ADDR_LOW         0x00
/* Chip restart after firmware download (Windows fn 0x29A0 + 0x001665,
 * chip_type==1 branch, disassembly-verified 2026-10-06):
 *   Sleep(2) → rst low 7ms → high → Sleep(10) → rst low 7ms → high → Sleep(180) */
#define FT9338_FW_RESTART_PULSE_MS   7
#define FT9338_FW_BOOT_DELAY_MS      180

static const FpIdEntry fte7001_id_table[] = {
  {
    .udev_types   = FPI_DEVICE_UDEV_SUBTYPE_SPIDEV,
    .spi_acpi_id  = "FTE7001",
  },
  { .udev_types = 0 },
};