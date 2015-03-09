/*
 *  linux/arch/arm/boot/compressed/head.S
 *
 *  Copyright (C) 1996-2002 Russell King
 *  Copyright (C) 2004 Hyok S. Choi (MPU support)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/*
 * include/linux/linkage.h
 * arch/arm/include/asm/assembler.h
 * */
#include <linux/linkage.h>
#include <asm/assembler.h>

	.arch	armv7-a
/*
 * Debugging stuff
 *
 * Note that these macros must not contain any code which is not
 * 100% relocatable.  Any attempt to do so will result in a crash.
 * Please select one of the following when turning on debugging.
 */
#ifdef DEBUG

#if defined(CONFIG_DEBUG_ICEDCC)

#if defined(CONFIG_CPU_V6) || defined(CONFIG_CPU_V6K) || defined(CONFIG_CPU_V7)
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c0, c5, 0
		.endm
#elif defined(CONFIG_CPU_XSCALE)
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c8, c0, 0
		.endm
#else
		.macro	loadsp, rb, tmp
		.endm
		.macro	writeb, ch, rb
		mcr	p14, 0, \ch, c1, c0, 0
		.endm
#endif

#else

#include CONFIG_DEBUG_LL_INCLUDE

		.macro	writeb,	ch, rb
		senduart \ch, \rb
		.endm

#if defined(CONFIG_ARCH_SA1100)
		.macro	loadsp, rb, tmp
		mov	\rb, #0x80000000	@ physical base address
#ifdef CONFIG_DEBUG_LL_SER3
		add	\rb, \rb, #0x00050000	@ Ser3
#else
		add	\rb, \rb, #0x00010000	@ Ser1
#endif
		.endm
#elif defined(CONFIG_ARCH_S3C24XX)
		.macro loadsp, rb, tmp
		mov	\rb, #0x50000000
		add	\rb, \rb, #0x4000 * CONFIG_S3C_LOWLEVEL_UART_PORT
		.endm
#else
		.macro	loadsp,	rb, tmp
		addruart \rb, \tmp
		.endm
#endif
#endif
#endif

		.macro	kputc,val
		mov	r0, \val
		bl	putc
		.endm

		.macro	kphex,val,len
		mov	r0, \val
		mov	r1, #\len
		bl	phex
		.endm

		.macro	debug_reloc_start
#ifdef DEBUG
		kputc	#'\n'
		kphex	r6, 8		/* processor id */
		kputc	#':'
		kphex	r7, 8		/* architecture id */
#ifdef CONFIG_CPU_CP15
		kputc	#':'
		mrc	p15, 0, r0, c1, c0
		kphex	r0, 8		/* control reg */
#endif
		kputc	#'\n'
		kphex	r5, 8		/* decompressed kernel start */
		kputc	#'-'
		kphex	r9, 8		/* decompressed kernel end  */
		kputc	#'>'
		kphex	r4, 8		/* kernel execution address */
		kputc	#'\n'
#endif
		.endm

		.macro	debug_reloc_end
#ifdef DEBUG
		kphex	r5, 8		/* end of kernel */
		kputc	#'\n'
		mov	r0, r4
		bl	memdump		/* dump 256 bytes at start of kernel */
#endif
		.endm
 /* 
  * 2014/5/17
  * start 섹션 시작 부분 윗부분은 전부 macro 정의
  * .section: start section의 시작부분으로 vmlinux.lds 의  .start과 연결된다. 섹션의 시작 부분으로 정의한다.
  * #alloc: allocatable
  * #execinstr: excutable 
  */
		.section ".start", #alloc, #execinstr
/*
 * sort out different calling conventions
 */
		.align
		.arm				@ Always enter in ARM state
start:
		.type	start,#function		@
		.rept	7					@ .rept n: .rept부터 .endr까지 n번 반복
		mov	r0, r0					@ 리누즈 할아버지께서 말하시길 다른 아키텍처에서 시작 부분이 0으로 셋팅 안될 경우가 있어 넣으셨다고 답변을 받았다고함. 
		.endr
   ARM(		mov	r0, r0		)		@ ARM()와 같은 부분은 컴파일 과정에서 설정된 아키텍처에 해당하는 경우만 컴파일 되는 부분.
   ARM(		b	1f		)			@ b (label)f/b: 브랜치 명령어로 f의 경우 아래에 존재하는 label로 b의 경우 위에 존재하는 라벨로 이동.
 THUMB(		adr	r12, BSYM(1f)	)
 THUMB(		bx	r12		)

		.word	0x016f2818		@ Magic numbers to help the loader
		.word	start			@ absolute load/run zImage address
		.word	_edata			@ zImage end address
 THUMB(		.thumb			)
1:
 ARM_BE8(	setend	be )			@ go BE8 if compiled for BE8
		mrs	r9, cpsr			@ cpsr : current program status register
#ifdef CONFIG_ARM_VIRT_EXT
		bl	__hyp_stub_install	@ get into SVC mode, reversibly
			/*! 하이퍼 바이저 익스텐션을 위한 초기화 */
#endif
		mov	r7, r1			@ save architecture ID 	
		mov	r8, r2			@ save atags pointer
			/* 커널 부팅시 넘겨준 파라미터(atags)들의 주소를 r0부터 차례로 넣어서 전달 */
			/* ARM sys. Dev.  guide p.137참고 */
		/*
		 * Booting from Angel - need to enter SVC mode and disable
		 * FIQs/IRQs (numeric definitions from angel arm.h source).
		 * We only do this if we were in user mode on entry.
		 * angel과 swi 0x123456에 대한 설명은 http://www.iamroot.org/xe/Kernel_8_ARM/57324 참고
		 */
		mrs	r2, cpsr		@ get current mode
		tst	r2, #3			@ not user?
			/*! r2 & #3 */
			/*! tst: arm.arch.p.716 참고 */
		bne	not_angel		@ if SVC mode, go to not_angel
		mov	r0, #0x17		@ angel_SWIreason_EnterSVC
 ARM(		swi	0x123456	)	@ angel_SWI_ARM	
 			/*! swi=소프트웨어 인터럽트 명령어 amr.arch.p.713 참고 */
			/*! angel debugging 모드로 동작을 위한 동작? */
 THUMB(		svc	0xab		)	@ angel_SWI_THUMB
not_angel:
		safe_svcmode_maskall r0
			/*! /arch/arm/include/asm/assembler.h 에 존재 */
		msr	spsr_cxsf, r9		@ Save the CPU boot mode in
			/*! SPSR = 모드가 바뀌기 전의 cpsr을 저장해둔 레지스터 */
		/*
		 * Note that some cache flushing and other stuff may
		 * be needed here - is there an Angel SWI call for this?
		 */

		/*
		 * some architecture specific code can be inserted
		 * by the linker here, but it should preserve r7, r8, and r9.
		 */

		.text

#ifdef CONFIG_AUTO_ZRELADDR
@ ZRE Address = TEXTADDR의 실질적인 물리주소
@ TEXTADDR = 커널의 가상 시작주소, 일반적으로 PAGE_OFFSET + 0x8000
@ 결론 : 
@ 참고 : http://www.iamroot.org/xe/Kernel_10_ARM/186592#comment_186806
@ 참고2 : http://www.iamroot.org/xe/index.php?mid=Kernel_10_ARM&document_srl=180812#comment_181518
		@ determine final kernel image address
		mov	r4, pc
		and	r4, r4, #0xf8000000		@ 압축되지 않은 커널 이미지 위치
		add	r4, r4, #TEXT_OFFSET		@ arm makefile 참고(0x8000),  kernel의 시작지점  r4 = kernel start adress in ram 
		@ #PAGE_OFFSET + #TEXT_OFFSET = 가상주소
#else
		ldr	r4, =zreladdr				@ CONFIG_AUTO_ZRELADDR이 정의되지 않았을 때, arch/arm/mach-exynos/Makefile.boot 참고
#endif

		
		/*
		 * Set up a page table only if it won't overwrite ourself.
		 * That means r4 < pc && r4 - 16k page directory > &_end.
		 * Given that r4 > &_end is most unfrequent, we add a rough
		 * additional 1MB of room for a possible appended DTB(device tree binary).
		 */
		@ 참고 : http://www.iamroot.org/xe/Kernel_10_ARM/173174
		mov	r0, pc			@ r0 = pc
		cmp	r0, r4			@ r0 r4 비교(pc와 r4 비교) (r4 = kernel image addr)
						@ r0 - r4 >= 0 이면 Carry Set, 아니면 Clear

		@! @1 현 실행 위치(pc) 보다 Image 위치가 크다면 재배치 불필요
		@! @2 아니면 남은 실행 코드와 다시 위치 비교

		@1
		@ r0 < r4 => pc가 Image보다 작다
		@ if (r0 < r4) {
		ldrcc	r0, LC0+32		@ r0 < r4 일 때 (LC0+32 = _end - restart + 16K + 1M)
			@ r0 <= (LC0+32 = restart부터 코드 끝까지의 크기 + PageTable 총 크기 + DTB영역)
			@ 1M는 위의 영문 주석처럼 DTB의 확장에 대비한 크기
		addcc	r0, r0, pc		@ r0 < r4 일 때 r0 = r0 + pc
			@ 현 pc에서 zImage를 저장할 상대위치를 r0에 더해서 저장
			@ 여기서 zImage는 restart부터 코드 마지막까지 즉, 아직 실행 X 고 앞으로 실행할 영역

		@2
		cmpcc	r4, r0
		@ }

		@if r4 < r0 {
		@ cache_on하라는 flag하는 것으로 보임 - not_relocated 부분에서 판단함
		orrcc	r4, r4, #1		@ remember we skipped cache_on
		@ }

		@else if r4 >= r0 {
		@ 재배치가 필요하지 않음
		@ Carry가 Set이면 lr(Link Register)에 리턴할 현 위치를 저장하고 cache_on으로 Branch
		blcs	cache_on
		@ }

restart:	adr	r0, LC0
		/*
		 * LC0:            .word   LC0                     @ r1
		 *                 .word   __bss_start             @ r2
		 *                 .word   _end                    @ r3
		 *                 .word   _edata                  @ r6
		 *                 .word   input_data_end - 4      @ r10 (inflated size location)
		 *                 .word   _got_start              @ r11
		 *                 .word   _got_end                @ ip 내부 프로시저 호출 스크래치 레지스터, r12
		 *                 .word   .L_user_stack_end       @ sp, r13
		 *                 .word   _end - restart + 16384 + 1024*1024
		 */
		@ ARM 레지스터의 이름 : http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dui0204ik/ch03s03s01.html
		@ r0 (LC0)에서 {}로 순서대로 넣는다.
		ldmia	r0, {r1, r2, r3, r6, r10, r11, r12}	@ LoadMultiIncrementAfter? 한번에 최대 7개
		ldr	sp, [r0, #28]		@ r0(LC0)의 8번째 요소를 Load (28/4 + 1 = 8)

		/*
		 * We might be running at a different address.  We need
		 * to fix up various pointers.
		 */
		@ 이동한 LC0의 위치를 보정하기 위한 코드
		@ r1은 LC0의 초기 위치, r0은 현재의 LC0 위치 (후술된 코드에서 재배치 후 Restart 호출함)
		@ r0= pc(c8) + 0x208      r1 = 0x2d8
		sub	r0, r0, r1		@ calculate the delta offset
		add	r6, r6, r0		@ _edata
		add	r10, r10, r0		@ inflated kernel size location

/********************************
 *     2014/06/14 start			*
 ********************************/		

		/*
		 * The kernel build system appends the size of the
		 * decompressed kernel at the end of the compressed data
		 * in little-endian form.
		 */
		/*!
		 * 압축 풀린 커널 사이즈가 압축된 커널의 뒤에 저장되어있다.
		 * 예를 들어 커널 사이즈가 0x12345678 일 경우
		 */
		ldrb	r9, [r10, #0]	
			/*! r9 = 0x0000_0078 */
		ldrb	lr, [r10, #1]	
			/*! lr = 0x0000_0056 */
		orr	r9, r9, lr, lsl #8
			/*! r9 = 0x0000_5678 */
		ldrb	lr, [r10, #2]
			/*! lr = 0x0000_0034 */
		ldrb	r10, [r10, #3]
			/*! r10 = 0x0000_0012 */
		orr	r9, r9, lr, lsl #16
			/*! r9 = 0x0034_5678 */
		orr	r9, r9, r10, lsl #24
			/*! r9 = 0x1234_5678 */

#ifndef CONFIG_ZBOOT_ROM
		/* malloc space is above the relocated stack (64k max) */
		add	sp, sp, r0
			/*! r0 = delta offset */
		add	r10, sp, #0x10000
			/*! r10 = malloc space */
#else
		/*
		 * With ZBOOT_ROM the bss/stack is non relocatable,
		 * but someone could still run this code from RAM,
		 * in which case our reference is _edata.
		 */
		mov	r10, r6		
			/*! r10 = r6 = _edata(.bss시작 주소) */
#endif

		mov	r5, #0			@ init dtb size to 0
			/*! 현재 dtb의 사이즈는 0으로 설정(아직 모르는 상태) */
#ifdef CONFIG_ARM_APPENDED_DTB
/*
 *   r0  = delta
 *   r2  = BSS start
 *   r3  = BSS end
 *   r4  = final kernel address (possibly with LSB set)
 *   r5  = appended dtb size (still unknown)
 *   r6  = _edata
 *   r7  = architecture ID
 *   r8  = atags/device tree pointer
 *   r9  = size of decompressed image
 *   r10 = end of this image, including  bss/stack/malloc space if non XIP
 *   r11 = GOT start
 *   r12 = GOT end
 *   sp  = stack pointer
 *
 * if there are device trees (dtb) appended to zImage, advance r10 so that the
 * dtb data will get relocated along with the kernel if necessary.
 */

		/*!
		 * DTB를 사용할지 결정하기 위해 매직넘버 검사.
		 */
		ldr	lr, [r6, #0]
			/*!
			 * 이미지의 끝(_edata) 에는 DTB를 사용할지 결정할 매직넘버가 들어 있다. 
			 * Kconfig참고. (APPENDED_DTB)
			 */

#ifndef __ARMEB__
		ldr	r1, =0xedfe0dd0		@ sig is 0xd00dfeed big endian
			/*! 
			 * r1 = DTB 매직넘버(sig)
			 * 비교해서 _edata 끝에 dtb를 붙여서 사용하는지 검사한다.(위 주석대로 kconfig 참고)
			 */
#else
		ldr	r1, =0xd00dfeed
			/*! 빅엔디안의 경우 sig를 반대로 받아온다. */
#endif
		cmp	lr, r1
			/*!  if lr != r1	dtb를 사용 안하면  dtb_check_done으로 점프 */
		bne	dtb_check_done		@ not found

/********************************************************
 *			 14/06/21 start								*
 ********************************************************/
#ifdef CONFIG_ARM_ATAG_DTB_COMPAT
		/*
		 * OK... Let's do some funky business here.
		 * If we do have a DTB appended to zImage, and we do have
		 * an ATAG list around, we want the later to be translated
		 * and folded into the former here.  To be on the safe side,
		 * let's temporarily move  the stack away into the malloc
		 * area.  No GOT fixup has occurred yet, but none of the
		 * code we're about to call uses any global variable.
		*/
		/*!
		 * r6 = _edata
		 * r8 = atags pointer
		 */
		add	sp, sp, #0x10000
			/*! malloc space 설정 */
		stmfd	sp!, {r0-r3, ip, lr}
			/*!
			 * 함수 콜을 위해 레지스터를 스택에 저장
			 * r0~r3(인자 잔달용 레지스터), ip(got_end), lr(링크 레지스터 저장) 
			 * got: 프로그램에 상주하는 모든 심볼에 대한 실제 주소
			 * 참고: http://devrok.tistory.com/2
			 */
		mov	r0, r8
			/*! 첫번째 인자: atags pointer */
		mov	r1, r6
			/*! 두번째 인자: _edata */
		sub	r2, sp, r6
			/*! stack + heap - 사용한 양 */
		bl	atags_to_fdt

		/*
		 * If returned value is 1, there is no ATAG at the location
		 * pointed by r8.  Try the typical 0x100 offset from start
		 * of RAM and hope for the best.
		 */
		/*! return value(r0) == 1 -> 다시 할 필요가 있음. */
		cmp	r0, #1
		sub	r0, r4, #TEXT_OFFSET
		bic	r0, r0, #1
		add	r0, r0, #0x100
			/*! 첫번째 인자: (압축 풀린 커널 위치 - 0x8000) & ~1 + 100 */
		mov	r1, r6
			/*! 두번째 인자: _edata */
		sub	r2, sp, r6
			/*! 세번째 인자: 사용 가능한 메모리 양 */
		@! if(r0 == 1) {
		bleq	atags_to_fdt
		@! }

		ldmfd	sp!, {r0-r3, ip, lr}
		sub	sp, sp, #0x10000
			/*! 스택에서 r0~r3, ip, lr 복원 */
#endif

		mov	r8, r6			@ use the appended device tree

		/*
		 * Make sure that the DTB doesn't end up in the final
		 * kernel's .bss area. To do so, we adjust the decompressed
		 * kernel size to compensate if that .bss size is larger
		 * than the relocated code.
		 */
		ldr	r5, =_kernel_bss_size
		adr	r1, wont_overwrite
		sub	r1, r6, r1
			/*! r1 = wont_overwrite ~ _edata 사이즈 */
		subs	r1, r5, r1
		@! if(r5 > r1 (c =1 & z = 0 in cpsr)) {
		addhi	r9, r9, r1
		@! }
		/*!
		 * r8 = _edata 
		 * r5 = 압축풀린 커널의 bss_size
		 * r1 = r5 - (wont_overwrite ~ _edata 사이즈)
		 * r9 = if -> 압축풀린 커널 사이즈 - r1
		 *    = else -> 압축풀린 커널 사이즈
		 */

		/* Get the dtb's size */
		ldr	r5, [r6, #4]
		/*! r5 = fdt_header->dt_total_size(dtb size) */

#ifndef __ARMEB__
		/* convert r5 (dtb size) to little endian */
		eor	r1, r5, r5, ror #16
		bic	r1, r1, #0x00ff0000
		mov	r5, r5, ror #8
		eor	r5, r5, r1, lsr #8
#endif

		/* preserve 64-bit alignment */
		add	r5, r5, #7
		bic	r5, r5, #7

		/* relocate some pointers past the appended dtb */
		/*! dtb 보상을 위한 위치 조절 */
		add	r6, r6, r5
		add	r10, r10, r5
		add	sp, sp, r5
dtb_check_done:
#endif

/*
 * Check to see if we will overwrite ourselves.
 *   r4  = final kernel address (possibly with LSB set)
 *   r9  = size of decompressed image
 *   r10 = end of this image, including  bss/stack/malloc space if non XIP
 * We basically want:
 *   r4 - 16k page directory >= r10 -> OK
 *   r4 + image length <= address of wont_overwrite -> OK
 * Note: the possible LSB in r4 is harmless here.
 */
		add	r10, r10, #16384	@ 0x4000
			/*! r10 = _end(.stack) + 0x10000(64k malloc) +0x4000(16k page directory) */
		@! if (r4 >= r10 + 16k page directory) {
		cmp	r4, r10
		bhs	wont_overwrite
			/*! hs -> c = 1 in cpsr */
		@! }
		add	r10, r4, r9
			/*! r10 = 압축 풀린 커널이 위치할 주소 + 압축 풀린 커널 사이즈 */
		adr	r9, wont_overwrite
			/*! r9 = wont_overwrite 라벨의 주소 */
		@! if(r4 + 압축 풀린 kernel size <= adress of wont_overwrite) {
		cmp	r10, r9	
		bls	wont_overwrite
			/*! ls -> c = 0 in cpsr */
		@! }

/*
 * Relocate ourselves past the end of the decompressed kernel.
 *   r6  = _edata
 *   r10 = end of the decompressed kernel
 * Because we always copy ahead, we need to do it from the end and go
 * backward in case the source and destination overlap.
 */
		/*
		 * Bump to the next 256-byte boundary with the size of
		 * the relocation code added. This avoids overwriting
		 * ourself when the offset is small.
		 */
		add	r10, r10, #((reloc_code_end - restart + 256) & ~255)
			/*! r10 = r10 + (restart 이 후 코드 크기 + 0x100 ) & 0xffff_ff00 */
			/*! 목적은 얼라인 맞추기 */
		bic	r10, r10, #255
			/*! r10 = r10 & !(0xff) */

		/* Get start of code we want to copy and align it down. */
		adr	r5, restart
			/*! r5 = &restart */
		bic	r5, r5, #31
			/*! 하위 5비트 클리어 */
			/*! 8byte 얼라인을 위한 비트 클리어 */

/* Relocate the hyp vector base if necessary */
#ifdef CONFIG_ARM_VIRT_EXT
	/*! 
	 * v7이상에서 부터 지원
	 * 해당 옵션에 대해 후기 때 더 자세히 다루기
	 */
		mrs	r0, spsr
			/*! r0 = spsr */
		and	r0, r0, #MODE_MASK
			/*! r0 = spsr의 모드 비트 */
		@! if(r0 != #HYP_MODE, ) {
		cmp	r0, #HYP_MODE
			/*! r0이 하이퍼바이저 모드인지 검사, 아닐경우 1: 로 점프*/
		bne	1f
		@! }

		bl	__hyp_get_vectors
		sub	r0, r0, r5
		add	r0, r0, r10
		bl	__hyp_set_vectors
1:
#endif
		/*!
		 * r5 = restart 주소(얼라인 된)
		 * r6 = _edata 주소(얼라인 된)
		 * r10 = malloc end
		 */

		sub	r9, r6, r5		@ size to copy
			/*! r9 = _edata - (restart addr)&!0x1f */
			add	r9, r9, #31		@ rounded up to a multiple
			bic	r9, r9, #31		@ ... of 32 bytes
				/*! 5비트 단위 올림 for 얼라인 */
				/*! restart ~ _edata 까지 32bytes 얼라인 */
			/*! r9 = restart ~ _edata(복사할 영역 사이즈) */
		add	r6, r9, r5
		add	r9, r9, r10
			/*! 
			 * r6 = restart + 복사할 영역 사이즈(정렬된 _edata)
			 * r9 = malloc end + 복사할 영역 사이즈(정렬된 restart)
			 */
		
		/*!
		 * 재배치 루프(1: ldmdb ~ bhi 1b)
		 * r6(edata)부터 복사해서 r9(재배치할 영역 끝 주소) 붙여넣기
		 * 자세한 설명은 후기 + wiki 참고
		 */
1:		ldmdb	r6!, {r0 - r3, r10 - r12, lr}
			/*! ldm : arm architecture p. 95 참고 */
		cmp	r6, r5
		stmdb	r9!, {r0 - r3, r10 - r12, lr}
		bhi	1b

		/*! 참고 : http://www.iamroot.org/xe/Kernel_10_ARM/179812 중간쯤 */
		/* Preserve offset to relocated code. */
		sub	r6, r9, r6
			/*! r6 = 재배치 영역까지 오프셋 */

#ifndef CONFIG_ZBOOT_ROM
		/* cache_clean_flush may use the stack, so relocate it */
		add	sp, sp, r6
			/*! sp 위치 조절 */
#endif

		tst	r4, #1
			/*! 
			 * not_angel의 재배치 검사 과정에서 cache_on을 안 해줬을 때
			 * r4에 1이 세트되어있음. 이 경우 z bit에 셋이 되어있지 않으므로 eq 실행 안됨.
			 */
		/*!
		 * 현재 아키텍처에 맞는 캐쉬 플러쉬 함수 콜
		 * cache_on이 실행 되었을 경우 cache_clean_flush 실행
		 */
		bleq	cache_clean_flush

		adr	r0, BSYM(restart)
		add	r0, r0, r6
		mov	pc, r0
			/*! pc = restart + offset */
/********************************************************
 *  		2014/06/14 end 								*
 ********************************************************/

wont_overwrite:
/*
 * If delta is zero, we are running at the address we were linked at.
 *   r0  = delta
 *   r2  = BSS start
 *   r3  = BSS end
 *   r4  = kernel execution address (possibly with LSB set)
 *   r5  = appended dtb size (0 if not present)
 *   r7  = architecture ID
 *   r8  = atags pointer
 *   r11 = GOT start
 *   r12 = GOT end
 *   sp  = stack pointer
 */
		orrs	r1, r0, r5
		@! if(재비치 안함(r0 == 0), dtb없음(dtb == 0)) {
		beq	not_relocated
		@! }
		add	r11, r11, r0
		add	r12, r12, r0

#ifndef CONFIG_ZBOOT_ROM
		/*
		 * If we're running fully PIC === CONFIG_ZBOOT_ROM = n,
		 * we need to fix up pointers into the BSS region.
		 * Note that the stack pointer has already been fixed up.
		 */
		add	r2, r2, r0
		add	r3, r3, r0
			/*! bss 재배치 */

		/*
		 * Relocate all entries in the GOT table.
		 * Bump bss entries to _edata + dtb size
		 */
		/*!
		 * 1:
		 * got 엔트리가 bss start ~ end 사이에 존재하면
		 * DTB 사이즈만큼 더해서 got 엔트리를 옮긴다.
		 */
1:		ldr	r1, [r11, #0]		@ relocate entries in the GOT
			/*! r1 = r11[0] */
		add	r1, r1, r0		@ This fixes up C references
		cmp	r1, r2			@ if entry >= bss_start &&
		@! if( c == 1) {
		cmphs	r3, r1			@       bss_end > entry
		@! if( c == 1 & z == 0) {
		addhi	r1, r1, r5		@    entry += dtb size
		@! } }
		str	r1, [r11], #4		@ next entry
			/*! r11 = r1, r11 += 4(포스트 인덱스, arm 책 p.91) */
		cmp	r11, r12
		@! if(c == 0 ){
		blo	1b
		@! }
		/* bump our bss pointers too */
		add	r2, r2, r5
		add	r3, r3, r5
			/*! bss 위치도 dtb 사이즈만큼 증가 */
		/*! bss, got 차이 참고: https://kldp.org/node/127967 */
#else

		/*
		 * Relocate entries in the GOT table.  We only relocate
		 * the entries that are outside the (relocated) BSS region.
		 */
1:		ldr	r1, [r11, #0]		@ relocate entries in the GOT
		cmp	r1, r2			@ entry < bss_start ||
		cmphs	r3, r1			@ _end < entry
		addlo	r1, r1, r0		@ table.  This fixes up the
		str	r1, [r11], #4		@ C references.
		cmp	r11, r12
		blo	1b
#endif

not_relocated:	mov	r0, #0
/*!
 * 1:
 * 비에스에스 스타트(r2)~ 엔드(r3) 초기화
 */
1:		str	r0, [r2], #4		@ clear bss
		str	r0, [r2], #4
		str	r0, [r2], #4
		str	r0, [r2], #4
		cmp	r2, r3
		blo	1b

		/*
		 * Did we skip the cache setup earlier?
		 * That is indicated by the LSB in r4.
		 * Do it now if so.
		 */
		tst	r4, #1 
		bic	r4, r4, #1
		@! if( r4의 첫번째 비트 == 1 ) {
		blne	cache_on
		@! }

/*
 * The C runtime environment should now be setup sufficiently.
 * Set up some pointers, and start decompressing.
 *   r4  = kernel execution address
 *   r7  = architecture ID
 *   r8  = atags pointer
 */
		mov	r0, r4
		mov	r1, sp			@ malloc space above stack
		add	r2, sp, #0x10000	@ 64k max
		mov	r3, r7
			/*!
			 * r0 = 압축 풀린 커널의 시작할 위치
			 * r1 = sp(malloc start)
			 * r2 = sp + 0x10000(64k, malloc end)
			 * r3 = 아키텍처 id
			 * void
			 * decompress_kernel(unsigned long output_start, unsigned long free_mem_ptr_p,
			 * unsigned long free_mem_ptr_end_p, int arch_id)
		 	 */
		bl	decompress_kernel
/********************************************************
 *		14/06/21 end									*
 *		14/06/28 start									*
 ********************************************************/
		bl	cache_clean_flush
			/*! 
			 * cache_clean 더티 비트가 1로 셋된 캐쉬를 메모리로 업데이트
			 * caxhe_flush 캐쉬라인의 더티비트를 0으로 리셋
			 * 참고: arm arch p.499
			 */
		bl	cache_off
			/*! 현재 이미지에서 캐쉬를 사용 다 했으므로  캐쉬 오프 */
		mov	r1, r7			@ restore architecture number
		mov	r2, r8			@ restore atags pointer

#ifdef CONFIG_ARM_VIRT_EXT
		mrs	r0, spsr		@ Get saved CPU boot mode
		and	r0, r0, #MODE_MASK
		cmp	r0, #HYP_MODE		@ if not booted in HYP mode...
		@! if(!HYP_MODE) {
		bne	__enter_kernel		@ boot kernel directly
		@! }

		adr	r12, .L__hyp_reentry_vectors_offset
		ldr	r0, [r12]
		add	r0, r0, r12

		bl	__hyp_set_vectors
		__HVC(0)			@ otherwise bounce to hyp mode

		b	.			@ should never be reached

		.align	2
.L__hyp_reentry_vectors_offset:	.long	__hyp_reentry_vectors - .
#else
		b	__enter_kernel
#endif

		.align	2
		.type	LC0, #object
@ Line of Code?
		@ (.word LC0)는 LC0의 주소를 지님
LC0:		.word	LC0			@ r1 추후에 restart 에서 Load함 r1로 (아래도)
		.word	__bss_start		@ r2
		.word	_end			@ r3
		.word	_edata			@ r6
		.word	input_data_end - 4	@ r10 (inflated size location)
		.word	_got_start		@ r11
		.word	_got_end		@ ip
		.word	.L_user_stack_end	@ sp
		.word	_end - restart + 16384 + 1024*1024
	       	@ 16384 = 16K (PageTable의 크기), 1024*1024 = 1M 완충공간
		@ _end = 이 실행 중인 코드의 끝 주소(추측), -> _end - restart = 실행할 남은 코드의 길이
		@ (*부가설명) PageTable의 크기가 16K인 이유는 PageTable 크기인 4byte가 4096개로
		@ 4GB를 커버하기 위함이다.
		.size	LC0, . - LC0

#ifdef CONFIG_ARCH_RPC
		.globl	params
params:		ldr	r0, =0x10000100		@ params_phys for RPC
		mov	pc, lr
		.ltorg
		.align
#endif

/*
 * Turn on the cache.  We need to setup some page tables so that we
 * can have both the I and D caches on.
 *
 * We place the page tables 16k down from the kernel execution address,
 * and we hope that nothing else is using it.  If we're using it, we
 * will go pop!
 *
 * On entry,
 *  r4 = kernel execution address
 *  r7 = architecture number
 *  r8 = atags pointer
 * On exit,
 *  r0, r1, r2, r3, r9, r10, r12 corrupted
 * This routine must preserve:
 *  r4, r7, r8
 */
		.align	5
@ cache_on 시작, r3에 8 의미는 0, 1, 2 -> 세번째 함수 즉, cach_on 함수
cache_on:	mov	r3, #8			@ cache_on function
		b	call_cache_fn		@ 현 Proc에 해당하는 cache_on 함수를 찾는 루틴

/*
 * Initialize the highest priority protection region, PR7
 * to cover all 32bit address and cacheable and bufferable.
 */
__armv4_mpu_cache_on:
		mov	r0, #0x3f		@ 4G, the whole
		mcr	p15, 0, r0, c6, c7, 0	@ PR7 Area Setting
		mcr 	p15, 0, r0, c6, c7, 1

		mov	r0, #0x80		@ PR7
		mcr	p15, 0, r0, c2, c0, 0	@ D-cache on
		mcr	p15, 0, r0, c2, c0, 1	@ I-cache on
		mcr	p15, 0, r0, c3, c0, 0	@ write-buffer on

		mov	r0, #0xc000
		mcr	p15, 0, r0, c5, c0, 1	@ I-access permission
		mcr	p15, 0, r0, c5, c0, 0	@ D-access permission

		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c7, c5, 0	@ flush(inval) I-Cache
		mcr	p15, 0, r0, c7, c6, 0	@ flush(inval) D-Cache
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						@ ...I .... ..D. WC.M
		orr	r0, r0, #0x002d		@ .... .... ..1. 11.1
		orr	r0, r0, #0x1000		@ ...1 .... .... ....

		mcr	p15, 0, r0, c1, c0, 0	@ write control reg

		mov	r0, #0
		mcr	p15, 0, r0, c7, c5, 0	@ flush(inval) I-Cache
		mcr	p15, 0, r0, c7, c6, 0	@ flush(inval) D-Cache
		mov	pc, lr

__armv3_mpu_cache_on:
		mov	r0, #0x3f		@ 4G, the whole
		mcr	p15, 0, r0, c6, c7, 0	@ PR7 Area Setting

		mov	r0, #0x80		@ PR7
		mcr	p15, 0, r0, c2, c0, 0	@ cache on
		mcr	p15, 0, r0, c3, c0, 0	@ write-buffer on

		mov	r0, #0xc000
		mcr	p15, 0, r0, c5, c0, 0	@ access permission

		mov	r0, #0
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		/*
		 * ?? ARMv3 MMU does not allow reading the control register,
		 * does this really work on ARMv3 MPU?
		 */
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
						@ .... .... .... WC.M
		orr	r0, r0, #0x000d		@ .... .... .... 11.1
		/* ?? this overwrites the value constructed above? */
		mov	r0, #0
		mcr	p15, 0, r0, c1, c0, 0	@ write control reg

		/* ?? invalidate for the second time? */
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

#ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
#define CB_BITS 0x08
#else
#define CB_BITS 0x0c
#endif

__setup_mmu:	sub	r3, r4, #16384		@ Page directory size
		bic	r3, r3, #0xff		@ Align the pointer
		bic	r3, r3, #0x3f00
/*
 * Initialise the page tables, turning on the cacheable and bufferable
 * bits for the RAM area only.
 */
		mov	r0, r3
		mov	r9, r0, lsr #18
		mov	r9, r9, lsl #18		@ start of RAM
		add	r10, r9, #0x10000000	@ a reasonable RAM size
		mov	r1, #0x12		@ XN|U + section mapping
		orr	r1, r1, #3 << 10	@ AP=11
		add	r2, r3, #16384
1:		cmp	r1, r9			@ if virt > start of RAM
		cmphs	r10, r1			@   && end of RAM > virt
		bic	r1, r1, #0x1c		@ clear XN|U + C + B
		orrlo	r1, r1, #0x10		@ Set XN|U for non-RAM
		orrhs	r1, r1, r6		@ set RAM section settings
		str	r1, [r0], #4		@ 1:1 mapping
		add	r1, r1, #1048576
		teq	r0, r2
		bne	1b
/*
 * If ever we are running from Flash, then we surely want the cache
 * to be enabled also for our execution instance...  We map 2MB of it
 * so there is no map overlap problem for up to 1 MB compressed kernel.
 * If the execution is in RAM then we would only be duplicating the above.
 */
		orr	r1, r6, #0x04		@ ensure B is set for this
		orr	r1, r1, #3 << 10
		mov	r2, pc
		mov	r2, r2, lsr #20
		orr	r1, r1, r2, lsl #20
		add	r0, r3, r2, lsl #2
		str	r1, [r0], #4
		add	r1, r1, #1048576
		str	r1, [r0]
		mov	pc, lr
ENDPROC(__setup_mmu)

@ Enable unaligned access on v6, to allow better code generation
@ for the decompressor C code:
__armv6_mmu_cache_on:
		mrc	p15, 0, r0, c1, c0, 0	@ read SCTLR
		bic	r0, r0, #2		@ A (no unaligned access fault)
		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
		mcr	p15, 0, r0, c1, c0, 0	@ write SCTLR
		b	__armv4_mmu_cache_on

__arm926ejs_mmu_cache_on:
#ifdef CONFIG_CPU_DCACHE_WRITETHROUGH
		mov	r0, #4			@ put dcache in WT mode
		mcr	p15, 7, r0, c15, c0, 0
#endif

__armv4_mmu_cache_on:
		mov	r12, lr
#ifdef CONFIG_MMU
		mov	r6, #CB_BITS | 0x12	@ U
		bl	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		orr	r0, r0, #0x5000		@ I-cache enable, RR cache replacement
		orr	r0, r0, #0x0030
 ARM_BE8(	orr	r0, r0, #1 << 25 )	@ big-endian page tables
		bl	__common_mmu_cache_on
		mov	r0, #0
		mcr	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
#endif
		mov	pc, r12

__armv7_mmu_cache_on:
		mov	r12, lr
#ifdef CONFIG_MMU
		mrc	p15, 0, r11, c0, c1, 4	@ read ID_MMFR0
		tst	r11, #0xf		@ VMSA
		movne	r6, #CB_BITS | 0x02	@ !XN
		blne	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		tst	r11, #0xf		@ VMSA
		mcrne	p15, 0, r0, c8, c7, 0	@ flush I,D TLBs
#endif
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		bic	r0, r0, #1 << 28	@ clear SCTLR.TRE
		orr	r0, r0, #0x5000		@ I-cache enable, RR cache replacement
		orr	r0, r0, #0x003c		@ write buffer
		bic	r0, r0, #2		@ A (no unaligned access fault)
		orr	r0, r0, #1 << 22	@ U (v6 unaligned access model)
						@ (needed for ARM1176)
#ifdef CONFIG_MMU
 ARM_BE8(	orr	r0, r0, #1 << 25 )	@ big-endian page tables
		mrcne   p15, 0, r6, c2, c0, 2   @ read ttb control reg
		orrne	r0, r0, #1		@ MMU enabled
		movne	r1, #0xfffffffd		@ domain 0 = client
		bic     r6, r6, #1 << 31        @ 32-bit translation system
		bic     r6, r6, #3 << 0         @ use only ttbr0
		mcrne	p15, 0, r3, c2, c0, 0	@ load page table pointer
		mcrne	p15, 0, r1, c3, c0, 0	@ load domain access control
		mcrne   p15, 0, r6, c2, c0, 2   @ load ttb control
#endif
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mcr	p15, 0, r0, c1, c0, 0	@ load control register
		mrc	p15, 0, r0, c1, c0, 0	@ and read it back
		mov	r0, #0
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mov	pc, r12

__fa526_cache_on:
		mov	r12, lr
		mov	r6, #CB_BITS | 0x12	@ U
		bl	__setup_mmu
		mov	r0, #0
		mcr	p15, 0, r0, c7, c7, 0	@ Invalidate whole cache
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c8, c7, 0	@ flush UTLB
		mrc	p15, 0, r0, c1, c0, 0	@ read control reg
		orr	r0, r0, #0x1000		@ I-cache enable
		bl	__common_mmu_cache_on
		mov	r0, #0
		mcr	p15, 0, r0, c8, c7, 0	@ flush UTLB
		mov	pc, r12

__common_mmu_cache_on:
#ifndef CONFIG_THUMB2_KERNEL
#ifndef DEBUG
		orr	r0, r0, #0x000d		@ Write buffer, mmu
#endif
		mov	r1, #-1
		mcr	p15, 0, r3, c2, c0, 0	@ load page table pointer
		mcr	p15, 0, r1, c3, c0, 0	@ load domain access control
		b	1f
		.align	5			@ cache line aligned
1:		mcr	p15, 0, r0, c1, c0, 0	@ load control register
		mrc	p15, 0, r0, c1, c0, 0	@ and read it back to
		sub	pc, lr, r0, lsr #32	@ properly flush pipeline
#endif

#define PROC_ENTRY_SIZE (4*5)

/*
 * Here follow the relocatable cache support functions for the
 * various processors.  This is a generic hook for locating an
 * entry and jumping to an instruction at the specified offset
 * from the start of the block.  Please note this is all position
 * independent code.
 *
 *  r1  = corrupted
 *  r2  = corrupted
 *  r3  = block offset
 *  r9  = corrupted
 *  r12 = corrupted
 */

		@ adr : 해당 라벨의 주소값을 저장
call_cache_fn:	adr	r12, proc_types
		@ proc_types는 Process ID, Mask와 해당하는 cache 함수가 있는 Table
#ifdef CONFIG_CPU_CP15
		@ mrc : Co Processor용 Mov
		mrc	p15, 0, r9, c0, c0	@ get processor ID
		/*! r9 = cp15의 값중 processor ID*/
#else
		ldr	r9, =CONFIG_PROCESSOR_ID
#endif
1:		ldr	r1, [r12, #0]		@ get value
		ldr	r2, [r12, #4]		@ get mask
		eor	r1, r1, r9		@ (real ^ match)
		tst	r1, r2			@       & mask
 ARM(		addeq	pc, r12, r3		) @ call cache function
 THUMB(		addeq	r12, r3			)
 THUMB(		moveq	pc, r12			) @ call cache function
		add	r12, r12, #PROC_ENTRY_SIZE
		b	1b

/*
 * Table for cache operations.  This is basically:
 *   - CPU ID match
 *   - CPU ID mask
 *   - 'cache on' method instruction
 *   - 'cache off' method instruction
 *   - 'cache flush' method instruction
 *
 * We match an entry using: ((real_id ^ match) & mask) == 0
 *
 * Writethrough caches generally only need 'on' and 'off'
 * methods.  Writeback caches _must_ have the flush method
 * defined.
 */
		.align	2
		.type	proc_types,#object
proc_types:
		.word	0x41000000		@ old ARM ID
		.word	0xff00f000
		mov	pc, lr			@ Return 위치로 복귀 (Cache가 없는 듯)
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41007000		@ ARM7/710
		.word	0xfff8fe00
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41807200		@ ARM720T (writethrough)
		.word	0xffffff00
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		mov	pc, lr
 THUMB(		nop				)

		.word	0x41007400		@ ARM74x
		.word	0xff00ff00
		W(b)	__armv3_mpu_cache_on
		W(b)	__armv3_mpu_cache_off
		W(b)	__armv3_mpu_cache_flush
		
		.word	0x41009400		@ ARM94x
		.word	0xff00ff00
		W(b)	__armv4_mpu_cache_on
		W(b)	__armv4_mpu_cache_off
		W(b)	__armv4_mpu_cache_flush

		.word	0x41069260		@ ARM926EJ-S (v5TEJ)
		.word	0xff0ffff0
		W(b)	__arm926ejs_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x00007000		@ ARM7 IDs
		.word	0x0000f000
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		@ Everything from here on will be the new ID system.

		.word	0x4401a100		@ sa110 / sa1100
		.word	0xffffffe0
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x6901b110		@ sa1110
		.word	0xfffffff0
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x56056900
		.word	0xffffff00		@ PXA9xx
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x56158000		@ PXA168
		.word	0xfffff000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x56050000		@ Feroceon
		.word	0xff0f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

#ifdef CONFIG_CPU_FEROCEON_OLD_ID
		/* this conflicts with the standard ARMv5TE entry */
		.long	0x41009260		@ Old Feroceon
		.long	0xff00fff0
		b	__armv4_mmu_cache_on
		b	__armv4_mmu_cache_off
		b	__armv5tej_mmu_cache_flush
#endif

		.word	0x66015261		@ FA526
		.word	0xff01fff1
		W(b)	__fa526_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__fa526_cache_flush

		@ These match on the architecture ID

		.word	0x00020000		@ ARMv4T
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x00050000		@ ARMv5TE
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv4_mmu_cache_flush

		.word	0x00060000		@ ARMv5TEJ
		.word	0x000f0000
		W(b)	__armv4_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv5tej_mmu_cache_flush

		.word	0x0007b000		@ ARMv6
		.word	0x000ff000
		W(b)	__armv6_mmu_cache_on
		W(b)	__armv4_mmu_cache_off
		W(b)	__armv6_mmu_cache_flush

		.word	0x000f0000		@ new CPU Id
		.word	0x000f0000
		W(b)	__armv7_mmu_cache_on
		W(b)	__armv7_mmu_cache_off
		W(b)	__armv7_mmu_cache_flush
					
		.word	0			@ unrecognised type
		.word	0
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)
		mov	pc, lr
 THUMB(		nop				)

		.size	proc_types, . - proc_types

		/*
		 * If you get a "non-constant expression in ".if" statement"
		 * error from the assembler on this line, check that you have
		 * not accidentally written a "b" instruction where you should
		 * have written W(b).
		 */
		.if (. - proc_types) % PROC_ENTRY_SIZE != 0
		.error "The size of one or more proc_types entries is wrong."
		.endif

/*
 * Turn off the Cache and MMU.  ARMv3 does not support
 * reading the control register, but ARMv4 does.
 *
 * On exit,
 *  r0, r1, r2, r3, r9, r12 corrupted
 * This routine must preserve:
 *  r4, r7, r8
 */
		.align	5
cache_off:	mov	r3, #12			@ cache_off function
		b	call_cache_fn

__armv4_mpu_cache_off:
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0	@ turn MPU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c10, 4	@ drain write buffer
		mcr	p15, 0, r0, c7, c6, 0	@ flush D-Cache
		mcr	p15, 0, r0, c7, c5, 0	@ flush I-Cache
		mov	pc, lr

__armv3_mpu_cache_off:
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0, 0	@ turn MPU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

__armv4_mmu_cache_off:
#ifdef CONFIG_MMU
		mrc	p15, 0, r0, c1, c0
		bic	r0, r0, #0x000d
		mcr	p15, 0, r0, c1, c0	@ turn MMU and cache off
		mov	r0, #0
		mcr	p15, 0, r0, c7, c7	@ invalidate whole cache v4
		mcr	p15, 0, r0, c8, c7	@ invalidate whole TLB v4
#endif
		mov	pc, lr

__armv7_mmu_cache_off:
		mrc	p15, 0, r0, c1, c0
#ifdef CONFIG_MMU
		bic	r0, r0, #0x000d
#else
		bic	r0, r0, #0x000c
#endif
		mcr	p15, 0, r0, c1, c0	@ turn MMU and cache off
		mov	r12, lr
		bl	__armv7_mmu_cache_flush
		mov	r0, #0
#ifdef CONFIG_MMU
		mcr	p15, 0, r0, c8, c7, 0	@ invalidate whole TLB
#endif
		mcr	p15, 0, r0, c7, c5, 6	@ invalidate BTC
		mcr	p15, 0, r0, c7, c10, 4	@ DSB
		mcr	p15, 0, r0, c7, c5, 4	@ ISB
		mov	pc, r12

/*
 * Clean and flush the cache to maintain consistency.
 *
 * On exit,
 *  r1, r2, r3, r9, r10, r11, r12 corrupted
 * This routine must preserve:
 *  r4, r6, r7, r8
 */
		.align	5
cache_clean_flush:
		mov	r3, #16
		b	call_cache_fn

__armv4_mpu_cache_flush:
		mov	r2, #1
		mov	r3, #0
		mcr	p15, 0, ip, c7, c6, 0	@ invalidate D cache
		mov	r1, #7 << 5		@ 8 segments
1:		orr	r3, r1, #63 << 26	@ 64 entries
2:		mcr	p15, 0, r3, c7, c14, 2	@ clean & invalidate D index
		subs	r3, r3, #1 << 26
		bcs	2b			@ entries 63 to 0
		subs 	r1, r1, #1 << 5
		bcs	1b			@ segments 7 to 0

		teq	r2, #0
		mcrne	p15, 0, ip, c7, c5, 0	@ invalidate I cache
		mcr	p15, 0, ip, c7, c10, 4	@ drain WB
		mov	pc, lr
		
__fa526_cache_flush:
		mov	r1, #0
		mcr	p15, 0, r1, c7, c14, 0	@ clean and invalidate D cache
		mcr	p15, 0, r1, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv6_mmu_cache_flush:
		mov	r1, #0
		mcr	p15, 0, r1, c7, c14, 0	@ clean+invalidate D
		mcr	p15, 0, r1, c7, c5, 0	@ invalidate I+BTB
		mcr	p15, 0, r1, c7, c15, 0	@ clean+invalidate unified
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv7_mmu_cache_flush:
		mrc	p15, 0, r10, c0, c1, 5	@ read ID_MMFR1
			/*! MMFR1 = 메모리 특성을 가진 코프로세서의 */
		tst	r10, #0xf << 16		@ hierarchical cache (ARMv7)
		mov	r10, #0
		beq	hierarchical
		mcr	p15, 0, r10, c7, c14, 0	@ clean+invalidate D
		b	iflush
hierarchical:
		mcr	p15, 0, r10, c7, c10, 5	@ DMB
		stmfd	sp!, {r0-r7, r9-r11}
		mrc	p15, 1, r0, c0, c0, 1	@ read clidr
		ands	r3, r0, #0x7000000	@ extract loc from clidr
		mov	r3, r3, lsr #23		@ left align loc bit field
		beq	finished		@ if loc is 0, then no need to clean
		mov	r10, #0			@ start clean at cache level 0
loop1:
		add	r2, r10, r10, lsr #1	@ work out 3x current cache level
		mov	r1, r0, lsr r2		@ extract cache type bits from clidr
		and	r1, r1, #7		@ mask of the bits for current cache only
		cmp	r1, #2			@ see what cache we have at this level
		blt	skip			@ skip if no cache, or just i-cache
		mcr	p15, 2, r10, c0, c0, 0	@ select current cache level in cssr
		mcr	p15, 0, r10, c7, c5, 4	@ isb to sych the new cssr&csidr
		mrc	p15, 1, r1, c0, c0, 0	@ read the new csidr
		and	r2, r1, #7		@ extract the length of the cache lines
		add	r2, r2, #4		@ add 4 (line length offset)
		ldr	r4, =0x3ff
		ands	r4, r4, r1, lsr #3	@ find maximum number on the way size
		clz	r5, r4			@ find bit position of way size increment
		ldr	r7, =0x7fff
		ands	r7, r7, r1, lsr #13	@ extract max number of the index size
loop2:
		mov	r9, r4			@ create working copy of max way size
loop3:
 ARM(		orr	r11, r10, r9, lsl r5	) @ factor way and cache number into r11
 ARM(		orr	r11, r11, r7, lsl r2	) @ factor index number into r11
 THUMB(		lsl	r6, r9, r5		)
 THUMB(		orr	r11, r10, r6		) @ factor way and cache number into r11
 THUMB(		lsl	r6, r7, r2		)
 THUMB(		orr	r11, r11, r6		) @ factor index number into r11
		mcr	p15, 0, r11, c7, c14, 2	@ clean & invalidate by set/way
		subs	r9, r9, #1		@ decrement the way
		bge	loop3
		subs	r7, r7, #1		@ decrement the index
		bge	loop2
skip:
		add	r10, r10, #2		@ increment cache number
		cmp	r3, r10
		bgt	loop1
finished:
		ldmfd	sp!, {r0-r7, r9-r11}
		mov	r10, #0			@ swith back to cache level 0
		mcr	p15, 2, r10, c0, c0, 0	@ select current cache level in cssr
iflush:
		mcr	p15, 0, r10, c7, c10, 4	@ DSB
		mcr	p15, 0, r10, c7, c5, 0	@ invalidate I+BTB
		mcr	p15, 0, r10, c7, c10, 4	@ DSB
		mcr	p15, 0, r10, c7, c5, 4	@ ISB
		mov	pc, lr

__armv5tej_mmu_cache_flush:
1:		mrc	p15, 0, r15, c7, c14, 3	@ test,clean,invalidate D cache
		bne	1b
		mcr	p15, 0, r0, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r0, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv4_mmu_cache_flush:
		mov	r2, #64*1024		@ default: 32K dcache size (*2)
		mov	r11, #32		@ default: 32 byte line size
		mrc	p15, 0, r3, c0, c0, 1	@ read cache type
		teq	r3, r9			@ cache ID register present?
		beq	no_cache_id
		mov	r1, r3, lsr #18
		and	r1, r1, #7
		mov	r2, #1024
		mov	r2, r2, lsl r1		@ base dcache size *2
		tst	r3, #1 << 14		@ test M bit
		addne	r2, r2, r2, lsr #1	@ +1/2 size if M == 1
		mov	r3, r3, lsr #12
		and	r3, r3, #3
		mov	r11, #8
		mov	r11, r11, lsl r3	@ cache line size in bytes
no_cache_id:
		mov	r1, pc
		bic	r1, r1, #63		@ align to longest cache line
		add	r2, r1, r2
1:
 ARM(		ldr	r3, [r1], r11		) @ s/w flush D cache
 THUMB(		ldr     r3, [r1]		) @ s/w flush D cache
 THUMB(		add     r1, r1, r11		)
		teq	r1, r2
		bne	1b

		mcr	p15, 0, r1, c7, c5, 0	@ flush I cache
		mcr	p15, 0, r1, c7, c6, 0	@ flush D cache
		mcr	p15, 0, r1, c7, c10, 4	@ drain WB
		mov	pc, lr

__armv3_mmu_cache_flush:
__armv3_mpu_cache_flush:
		mov	r1, #0
		mcr	p15, 0, r1, c7, c0, 0	@ invalidate whole cache v3
		mov	pc, lr

/*
 * Various debugging routines for printing hex characters and
 * memory, which again must be relocatable.
 */
#ifdef DEBUG
		.align	2
		.type	phexbuf,#object
phexbuf:	.space	12
		.size	phexbuf, . - phexbuf

@ phex corrupts {r0, r1, r2, r3}
phex:		adr	r3, phexbuf
		mov	r2, #0
		strb	r2, [r3, r1]
1:		subs	r1, r1, #1
		movmi	r0, r3
		bmi	puts
		and	r2, r0, #15
		mov	r0, r0, lsr #4
		cmp	r2, #10
		addge	r2, r2, #7
		add	r2, r2, #'0'
		strb	r2, [r3, r1]
		b	1b

@ puts corrupts {r0, r1, r2, r3}
puts:		loadsp	r3, r1
1:		ldrb	r2, [r0], #1
		teq	r2, #0
		moveq	pc, lr
2:		writeb	r2, r3
		mov	r1, #0x00020000
3:		subs	r1, r1, #1
		bne	3b
		teq	r2, #'\n'
		moveq	r2, #'\r'
		beq	2b
		teq	r0, #0
		bne	1b
		mov	pc, lr
@ putc corrupts {r0, r1, r2, r3}
putc:
		mov	r2, r0
		mov	r0, #0
		loadsp	r3, r1
		b	2b

@ memdump corrupts {r0, r1, r2, r3, r10, r11, r12, lr}
memdump:	mov	r12, r0
		mov	r10, lr
		mov	r11, #0
2:		mov	r0, r11, lsl #2
		add	r0, r0, r12
		mov	r1, #8
		bl	phex
		mov	r0, #':'
		bl	putc
1:		mov	r0, #' '
		bl	putc
		ldr	r0, [r12, r11, lsl #2]
		mov	r1, #8
		bl	phex
		and	r0, r11, #7
		teq	r0, #3
		moveq	r0, #' '
		bleq	putc
		and	r0, r11, #7
		add	r11, r11, #1
		teq	r0, #7
		bne	1b
		mov	r0, #'\n'
		bl	putc
		cmp	r11, #64
		blt	2b
		mov	pc, r10
#endif

		.ltorg

#ifdef CONFIG_ARM_VIRT_EXT
.align 5
__hyp_reentry_vectors:
		W(b)	.			@ reset
		W(b)	.			@ undef
		W(b)	.			@ svc
		W(b)	.			@ pabort
		W(b)	.			@ dabort
		W(b)	__enter_kernel		@ hyp
		W(b)	.			@ irq
		W(b)	.			@ fiq
#endif /* CONFIG_ARM_VIRT_EXT */

__enter_kernel:
		mov	r0, #0			@ must be 0
 ARM(		mov	pc, r4	)		@ call kernel
 		/*! 압축풀린 커널로 점프 */
 THUMB(		bx	r4	)		@ entry point is always ARM

reloc_code_end:

		.align
		.section ".stack", "aw", %nobits
.L_user_stack:	.space	4096
.L_user_stack_end:
