#!/bin/bash
#make -j8 ARCH=arm CROSS_COMPILE=arm-linux-gnueabi- all
make -j8 ARCH=arm CROSS_COMPILE=arm-none-eabi- all
