# FocalTech FTE7001 / FT9338 Linux Driver (downstream libfprint)

> **Downstream tree** based on the official libfprint `v1.94.10` release,
> adding support for the FocalTech **FT9338** fingerprint sensor
> (ACPI `_HID`: **FTE7001**, found in the One Mix 3 and similar
> Cherry Trail / Braswell tablets).
>
> The delta against upstream is intentionally small and reviewable:
>
> - `libfprint/drivers/fte7001.c` / `fte7001.h` — FpDevice driver:
>   cold-boot firmware upload (volatile RAM firmware), pure-5B polling
>   with suspend soft-wake watchdog and double-frame finger confirmation.
> - `libfprint/drivers/fte7001-matcher.c` / `.h` — self-contained
>   keypoint matcher (DoG + descriptors + RANSAC, pure C99, no GLib),
>   calibrated on the real sensor (leave-one-out: genuine min 13.1,
>   impostor max 3.1, threshold 7.0). The sensor is 88×88 and yields
>   ~1 NBIS minutia per frame, so the FpImageDevice+NBIS path cannot
>   work; the driver therefore implements enroll/verify itself.
> - `libfprint/drivers/ft9338-firmware.inc` — vendor firmware blob
>   (see licensing note in the file header).
> - SPI core additions (backported from the fte3600 downstream fork):
>   `fpi_spi_transfer_set_full_duplex()` for single-CS full-duplex
>   transfers, `fpi_spi_transfer_set_sensitive()` to redact biometric
>   data from debug logs, and `fpi_print_get_type()`.
> - Device core: allow `fp_device_close()` on a suspended device. Suspend
>   has already cancelled every running action, so refusing the close
>   left the device permanently stuck open after a suspend that
>   interrupted a verify (observed: lock-screen fingerprint became
>   silently dead until fprintd was restarted). Resume is now idempotent.
> - Meson registration of the `fte7001` SPI driver (needs libgpiod ≥ 2.0
>   for the reset GPIO).
> - `tests/fte7001/` — standalone matcher regression test (synthetic
>     fixtures only, no biometric data).
>
> Everything else is pristine upstream libfprint; see the upstream
> README below. This tree supersedes the earlier
> `fte7001-linux-driver` repository (up to its v2.0), which built
> against a third-party fork; releases here continue that version
> line (starting at v2.1) while tracking official libfprint releases
> directly.

## Build

```bash
meson setup build -Ddrivers=fte7001 -Dudev_rules=disabled \
    -Dintrospection=false -Ddoc=false --prefix=/usr
ninja -C build
```

Requirements: libgpiod ≥ 2.0 plus the usual libfprint dependencies.
Install the built `libfprint-2.so` with your distribution's stock
fprintd (1.94.x) — fprintd itself is not patched.

The spidev buffer size must be raised (e.g. `spidev bufsiz=65536`
in `/etc/modprobe.d/spidev.conf`) for the 7.5 KB image transfers.

## Matcher test

```bash
gcc -O2 -Wall -I libfprint/drivers -o /tmp/matcher-test \
    tests/fte7001/matcher-test.c libfprint/drivers/fte7001-matcher.c -lm
/tmp/matcher-test
```

---

<div align="center">

# LibFPrint

*LibFPrint is part of the **[FPrint][Website]** project.*

<br/>
<div align="center">

# LibFPrint

*LibFPrint is part of the **[FPrint][Website]** project.*

<br/>

[![Button Website]][Website]
[![Button Documentation]][Documentation]

[![Button Supported]][Supported]
[![Button Unsupported]][Unsupported]

[![Button Contribute]][Contribute]
[![Button Contributors]][Contributors]

</div>

## History

**LibFPrint** was originally developed as part of an
academic project at the **[University Of Manchester]**.

It aimed to hide the differences between consumer
fingerprint scanners and provide a single uniform
API to application developers.

## Goal

The ultimate goal of the **FPrint** project is to make
fingerprint scanners widely and easily usable under
common Linux environments.

## License

`Section 6` of the license states that for compiled works that use
this library, such works must include **LibFPrint** copyright notices
alongside the copyright notices for the other parts of the work.

**LibFPrint** includes code from **NIST's** **[NBIS]** software distribution.

We include **Bozorth3** from the **[US Export Controlled]**
distribution, which we have determined to be fine
being shipped in an open source project.

## Get in *touch*

 - [IRC] - `#fprint` @ `irc.oftc.net`
 - [Matrix] - `#fprint:matrix.org` bridged to the IRC channel
 - [MailingList] - low traffic, not much used these days

<br/>

<div align="right">

[![Badge License]][License]

</div>


<!----------------------------------------------------------------------------->

[Documentation]: https://fprint.freedesktop.org/libfprint-dev/
[Contributors]: https://gitlab.freedesktop.org/libfprint/libfprint/-/graphs/master
[Unsupported]: https://gitlab.freedesktop.org/libfprint/wiki/-/wikis/Unsupported-Devices
[Supported]: https://fprint.freedesktop.org/supported-devices.html
[Website]: https://fprint.freedesktop.org/
[MailingList]: https://lists.freedesktop.org/mailman/listinfo/fprint
[IRC]: ircs://irc.oftc.net:6697/#fprint
[Matrix]: https://matrix.to/#/#fprint:matrix.org

[Contribute]: ./HACKING.md
[License]: ./COPYING

[University Of Manchester]: https://www.manchester.ac.uk/
[US Export Controlled]: https://fprint.freedesktop.org/us-export-control.html
[NBIS]: http://fingerprint.nist.gov/NBIS/index.html


<!---------------------------------[ Badges ]---------------------------------->

[Badge License]: https://img.shields.io/badge/License-LGPL2.1-015d93.svg?style=for-the-badge&labelColor=blue


<!---------------------------------[ Buttons ]--------------------------------->

[Button Documentation]: https://img.shields.io/badge/Documentation-04ACE6?style=for-the-badge&logoColor=white&logo=BookStack
[Button Contributors]: https://img.shields.io/badge/Contributors-FF4F8B?style=for-the-badge&logoColor=white&logo=ActiGraph
[Button Unsupported]: https://img.shields.io/badge/Unsupported_Devices-EF2D5E?style=for-the-badge&logoColor=white&logo=AdBlock
[Button Contribute]: https://img.shields.io/badge/Contribute-66459B?style=for-the-badge&logoColor=white&logo=Git
[Button Supported]: https://img.shields.io/badge/Supported_Devices-428813?style=for-the-badge&logoColor=white&logo=AdGuard
[Button Website]: https://img.shields.io/badge/Homepage-3B80AE?style=for-the-badge&logoColor=white&logo=freedesktopDotOrg
