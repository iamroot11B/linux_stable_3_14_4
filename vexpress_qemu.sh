#!/bin/bash
qemu-system-arm -M vexpress-a9 -cpu cortex-a9 -m 128M -kernel arch/arm/boot/zImage -initrd rootfs.img.gz -serial stdio -append "root=/dev/ram rdinit=/bin/sh console=ttyAMA0"
