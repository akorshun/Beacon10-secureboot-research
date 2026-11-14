# DeepSeek-suggested experiments — all tested/closed (2026-11-14)

Follow-up on external suggestions for achieving full OpenWrt autoboot. All four
are now conclusively closed. Notable: experiment 1 was tested **without any UART
interaction** — the U-Boot env partition (p17) was patched directly from the
custom rootfs (CRC32 recompute over `[4:]`, no flag byte, NUL-separated
`name=value`, pad to original size; written to both p17 and p33). Method
reusable for any future env experiment.

## 1. `preboot` env variable — DEAD (tested on hardware)

Standard U-Boot runs `preboot` before autoboot. Suggestion: put the OpenWrt
`bootm` sequence there. Result: **the vendor rewrote the entire autoboot flow —
`preboot` never executes**, same as `bootcmd`. Verified: env patched with
`preboot=setenv bootargs ...root=PARTLABEL=owrt_rootfs...; mmc dev 0; mmc read
0x50000000 0x1fa000 0x20000; bootm 0x50000000; bootipq` (both env copies), clean
reboot — UART shows the plain bootipq flow, no preboot output, no mmc read of
p36, kernel = stock 5.4.164, custom rootfs via `fsbootargs` as before.

The env-patch method itself (no UART needed):
```sh
# from the custom rootfs (root=/dev/mmcblk0p34):
mknod /dev/mmcblk0p17 b 179 17   # devtmpfs is absent; block nodes must exist
dd if=/dev/mmcblk0p17 | parse: [crc32 LE][NUL-separated name=value...]
# add/replace variable, pad with NULs to original 256 KiB, recompute CRC over [4:]
dd of=/dev/mmcblk0p17  +  same for p33 (backup env copy)
```

## 2. netconsole — DEAD (not compiled in)

No `netconsole`/`ncip`/`nc_port`/`NetConsole` strings anywhere in APPSBL; no
UDP-console code. Checked statically; nothing to test on hardware.

## 3. `bootipq` arguments — DEAD (no arguments exist)

The command table entry is `bootipq` → "bootipq from flash device" — bare
description, no usage line, no subcommands/slot arguments (QSDK takes its slot
arguments internally, not from the CLI). `secure_authenticate` is the standalone
svc1/cmd0x1f MBN-ROOTFS auth (already probed, rejects kernel containers).

## 4. "Differential" HLOS container — DEAD (covered by §7c fuzzing)

Suggestion: keep the signed bytes intact and only redirect `phdr2.p_offset`/
`p_vaddr` into the partition tail. Our §7c fuzzing already mutated the ELF
header and program-header fields (76 variants): all phdr mutations → clean
`Kernel image authentication failed` — the phdr table IS covered by the
signature/hash chain. Moving the load pointer is just another phdr mutation.
(The two hangs were phdr1 metadata descriptor out-of-bounds → QSEE DoS, §7c.)

## Bottom line

Autoboot of unsigned kernels is impossible by env or container tricks: the
vendor autoboot runs `bootipq` unconditionally (bootcmd/preboot ignored,
netconsole absent, bootipq has no unsigned-load variant, phdr table is signed).
OpenWrt 6.18 still requires the UART `bootm` path. The persistent no-UART option
remains the §7f custom rootfs on the signed stock kernel.
