#!/bin/sh
/bin/busybox mkdir -p /proc /sys /tmp /etc/dropbear /dev/pts /stock /root
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devpts devpts /dev/pts
/bin/busybox mount -t squashfs -o ro /dev/mmcblk0p26 /stock
/bin/busybox echo ===CUSTOMROOT-BOOT-OK=== > /dev/console
/sbin/myinsmod qca-ssdk > /dev/console 2>&1
/sbin/myinsmod qca-nss-dp > /dev/console 2>&1
/bin/busybox sleep 3
/bin/busybox echo ===ETH-CONFIG=== > /dev/console
/bin/busybox ifconfig eth0 192.168.12.1 netmask 255.255.255.0 up
/bin/busybox ifconfig eth1 192.168.13.1 netmask 255.255.255.0 up
/bin/busybox ifconfig eth2 192.168.16.1 netmask 255.255.255.0 up
/bin/busybox ifconfig eth3 192.168.14.1 netmask 255.255.255.0 up
/usr/sbin/dropbear -R -p 2222 -B > /dev/console 2>&1
/bin/busybox echo ===DROPBEAR-STARTED=== > /dev/console
while true; do
  /bin/busybox sh </dev/console >/dev/console 2>&1
  /bin/busybox sleep 1
done
