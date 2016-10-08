#ifndef _UAPI_LINUX_KERNEL_H
#define _UAPI_LINUX_KERNEL_H

#include <linux/sysinfo.h>

/*
 * 'kernel.h' contains some often-used function prototypes etc
 */
#define __ALIGN_KERNEL(x, a)		__ALIGN_KERNEL_MASK(x, (typeof(x))(a) - 1)
/*! 2016.10.08 study -ing */
	/*! align_mask는, (x^2-1)인 수를 받아서 (x^2)의 배수로 올림(ALIGN) 한다 */
#define __ALIGN_KERNEL_MASK(x, mask)	(((x) + (mask)) & ~(mask))


#endif /* _UAPI_LINUX_KERNEL_H */
