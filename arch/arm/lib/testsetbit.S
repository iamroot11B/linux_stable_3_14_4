/*
 *  linux/arch/arm/lib/testsetbit.S
 *
 *  Copyright (C) 1995-1996 Russell King
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/linkage.h>
#include <asm/assembler.h>
#include "bitops.h"
                .text
/*! 2015.01.30 study -ing
	해당 비트를 set하고, 해당 비트가 1이었으면 1 리턴, 해당 비트가 0 이었으면 0 리턴
	*/
testop	_test_and_set_bit, orreq, streq
