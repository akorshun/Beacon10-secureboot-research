# UART-free persistent custom rootfs on Nokia Beacon 10 (§8)

**Status:** WORKING — verified with two consecutive reboots, no UART interaction
**Date:** 2026-11-14
**Device:** router #2 (SN ALCLEB4CE79F), stock signed kernel + custom ext4 rootfs on p34 (`opt` partition)

## The idea

The stock kernel is signed (fused secure boot — cannot be replaced, see §7b-d),
**but** the `fsbootargs` U-Boot env variable is appended to the kernel cmdline on
**every boot** (`root=`, `init=` reach the kernel — verified). The rootfs partition
itself is **not signature-verified**. Therefore:

```
signed stock kernel (boots always)  +  attacker-controlled cmdline (env)  +  unsigned rootfs (p34)
= persistent custom system, no UART, survives reboots
```

## How it works

1. **U-Boot** runs `bootipq` every boot → authenticates the signed kernel via QSEE →
   appends `fsbootargs` to the cmdline → kernel starts.
2. Kernel mounts `root=/dev/mmcblk0p34` (ext4, 504 MiB — the `opt` partition, almost
   empty on stock) and runs `init=/init` — **our** script.
3. `/init` mounts `/proc`, `/sys`, `/dev/pts`, mounts the stock rootfs (p26, squashfs)
   read-only at `/stock`, loads the network drivers (`qca-ssdk.ko` → `qca-nss-dp.ko`)
   with a **static musl `myinsmod`** (the vendor busybox has NO insmod applet, and
   OpenWrt's kmodloader fails silently in this environment), brings up the LAN ports,
   starts dropbear on :2222 with our key, and finally runs a **respawn loop** shell on
   `/dev/console` — the init process never exits, so the kernel can never panic from
   a dead init.

## Building the rootfs (from stock root shell, all done over SSH)

```sh
mkfs.ext4 -F /dev/mmcblk0p34
mount /dev/mmcblk0p34 /mnt
mkdir -p /mnt/{bin,lib,sbin,usr/sbin,etc/dropbear,dev/pts,proc,sys,tmp,stock,root}
cp /bin/busybox /mnt/bin/            # vendor busybox (musl-dynamic, PAM)
cp /usr/sbin/dropbear /mnt/usr/sbin/
cp /lib/ld-musl-aarch64.so.1 /lib/libgcc_s.so.1 /mnt/lib/
cp /usr/lib/libpam.so.0 /usr/lib/libpam_misc.so.0 /usr/lib/libpamc.so.0 /mnt/lib/
cp /lib/libubox.so /mnt/lib/
cp /sbin/kmodloader /mnt/sbin/       # plus /sbin/insmod -> kmodloader symlink
cp -r /lib/modules/5.4.164 /mnt/lib/modules/       # 27.8 MB of .ko (no modules.dep on stock!)
cp /etc/modules.d /mnt/etc/          # for kmodloader
ln -s busybox /mnt/bin/sh            # CRITICAL: shebang #!/bin/sh of /init
# device nodes — devtmpfs is NOT in the kernel, /dev would otherwise be empty:
mknod /mnt/dev/console c 5 1; chmod 622 /mnt/dev/console
mknod /mnt/dev/null c 1 3; chmod 666 /mnt/dev/null
mknod /mnt/dev/zero c 1 5; mknod /mnt/dev/urandom c 1 9; mknod /mnt/dev/random c 1 8
mknod /mnt/dev/tty c 5 0
printf 'root:x:0:0:root:/root:/bin/sh\n' > /mnt/etc/passwd
printf 'root:x:0:\n' > /mnt/etc/group
echo '<our ssh key>' > /mnt/etc/dropbear/authorized_keys; chmod 600 /mnt/etc/dropbear/authorized_keys
# busybox applet symlinks (no --install in vendor build):
for A in ls grep cat head tail ps kill sleep sync mount umount mv cp rm mkdir rmdir \
         touch chmod chown date df dmesg du echo env free id ln netstat ping printf \
         uname uptime vi wc which find awk sed tar gzip gunzip; do
  ln -sf busybox /mnt/bin/$A
done
# static module loader (finit_module syscall; built via CI musl-gcc, see myinsmod.c):
# -> /mnt/sbin/myinsmod
# /init -> init_v6 (repo vtysh_re/init_v6)
fw_setenv fsbootargs 'root=/dev/mmcblk0p34 init=/init rw'
reboot
```

## Network layout (init v6)

| port | iface | address | note |
|---|---|---|---|
| 0 | eth0 | 192.168.12.1 | |
| 1 | eth1 | 192.168.13.1 | |
| 2 | eth2 | 192.168.16.1 | |
| 3 | eth3 | 192.168.14.1 | the port used for install/testing |

**ARP-flux gotcha:** assigning the SAME IP to all 4 interfaces silently breaks
connectivity (kernel answers ARP through the wrong port, the peer never learns L2
path). Each interface needs its own subnet — verified the hard way.

SSH: `ssh -p 2222 -i nokiakey root@192.168.14.1` (dropbear `-B`, key auth).

## Boot-chain visibility

- `fsbootargs` is **applied on every boot** (marker test: extra tokens appear in
  `/proc/cmdline`).
- U-Boot 2016 QSDK uses the **simple parser**: `;` inside `${fsbootargs}` is NOT
  re-split after variable expansion — hush-style command injection does NOT work,
  but full cmdline control does.
- `root=` and `init=` from `fsbootargs` override the values bootipq constructs
  (later cmdline args win).

## Failure modes encountered (all fixed)

| failure | cause | fix |
|---|---|---|
| `Requested init /init failed (error -2)` | `/init` shebang → no `/bin/sh` symlink | `ln -s busybox /bin/sh` |
| `Error relocating /init: misc_conv: symbol not found` | busybox needs `libpam_misc.so.0` (PAM build) | copy `libpam_misc.so.0` (check `ldd /bin/busybox`) |
| `insmod: applet not found` | vendor busybox has no insmod applet; kmodloader fails silently (ulog→syslog) in this env | static `myinsmod` (CI-built, `finit_module`) |
| `mount none on /dev failed: No such device` | no devtmpfs in kernel | mknod the device nodes into the ext4 image |
| markers swallowed, `sh </dev/console` → EOF → `Attempted to kill init! exitcode=0` | empty `/dev` → `>/dev/console` created a REGULAR FILE | real char device nodes + respawn loop |
| network silent, no ARP replies | same IP on eth0-3 (ARP flux) | unique subnet per interface |
| ext4 "recovery complete" ate files after panic reboots | journal replay during crash loops | verify contents after every failed-boot episode |

## Recovery

If the rootfs ever fails to boot: the **eMMC read-glitch** (short a specific via
near the SkyHigh S40FC004C chip ~2-3 s after power-on, hold 5-10 s) corrupts GPT
reads → bootipq fails → **U-Boot prompt without any password** (the NOKIA console
`en` login is broken by vendor design, see §7e) → run `tools/fix_full.py` on the PC:
it restores the GPT (705 UART commands), deletes `fsbootargs`, `saveenv` (works
only with intact GPT), reboots to stock. Note: `saveenv` FAILS while the GPT is
corrupted — GPT restore must come first.

## What this does NOT give

This is **not** upstream OpenWrt: the kernel is the signed vendor 5.4.164.
OpenWrt 6.18 still requires UART (`bootm` bypasses the bootipq auth; nothing else
does). This path provides a persistent, UART-free, attacker-controlled userland on
the stock kernel — from a one-time `fw_setenv` (which the web-UI race of §V4
could also perform).

## Security relevance (for the PSIRT report)

- one-time root (CVE-2025-9974 race) → `fw_setenv fsbootargs` → **every subsequent
  boot runs attacker-controlled userland on the signed kernel** — persistence that
  survives firmware-controlled A/B slot switching (both slots boot the same p34).
- `fsbootargs` survives `sh img` slot toggles and factory-config resets of the
  rootfs (env is in APPSBLENV, p17+p33).
