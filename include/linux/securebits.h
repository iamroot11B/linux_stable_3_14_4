#ifndef _LINUX_SECUREBITS_H
#define _LINUX_SECUREBITS_H 1

#include <uapi/linux/securebits.h>
/*! 2017. 8.12 study -ing */
#define issecure(X)		(issecure_mask(X) & current_cred_xxx(securebits))
#endif /* !_LINUX_SECUREBITS_H */
