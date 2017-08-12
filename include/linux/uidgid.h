#ifndef _LINUX_UIDGID_H
#define _LINUX_UIDGID_H

/*
 * A set of types for the internal kernel types representing uids and gids.
 *
 * The types defined in this header allow distinguishing which uids and gids in
 * the kernel are values used by userspace and which uid and gid values are
 * the internal kernel values.  With the addition of user namespaces the values
 * can be different.  Using the type system makes it possible for the compiler
 * to detect when we overlook these differences.
 *
 */
#include <linux/types.h>
#include <linux/highuid.h>

struct user_namespace;
extern struct user_namespace init_user_ns;

typedef struct {
	uid_t val;
} kuid_t;


typedef struct {
	gid_t val;
} kgid_t;
/*! 2017. 8.12 study -ing */
#define KUIDT_INIT(value) (kuid_t){ value }
#define KGIDT_INIT(value) (kgid_t){ value }

/*! 2017. 6. 3 study -ing */
static inline uid_t __kuid_val(kuid_t uid)
{
	return uid.val;
}
/*! 2017. 6. 3 study -ing */
static inline gid_t __kgid_val(kgid_t gid)
{
	return gid.val;
}

#define GLOBAL_ROOT_UID KUIDT_INIT(0)
#define GLOBAL_ROOT_GID KGIDT_INIT(0)

#define INVALID_UID KUIDT_INIT(-1)
#define INVALID_GID KGIDT_INIT(-1)

/*! 2017. 6. 3 study -ing */
static inline bool uid_eq(kuid_t left, kuid_t right)
{
	return __kuid_val(left) == __kuid_val(right);
}
/*! 2017. 6. 3 study -ing */
static inline bool gid_eq(kgid_t left, kgid_t right)
{
	return __kgid_val(left) == __kgid_val(right);
}

static inline bool uid_gt(kuid_t left, kuid_t right)
{
	return __kuid_val(left) > __kuid_val(right);
}

/*! 2017. 6.17 study -ing */
static inline bool gid_gt(kgid_t left, kgid_t right)
{
	return __kgid_val(left) > __kgid_val(right);
}

static inline bool uid_gte(kuid_t left, kuid_t right)
{
	return __kuid_val(left) >= __kuid_val(right);
}

static inline bool gid_gte(kgid_t left, kgid_t right)
{
	return __kgid_val(left) >= __kgid_val(right);
}

static inline bool uid_lt(kuid_t left, kuid_t right)
{
	return __kuid_val(left) < __kuid_val(right);
}

/*! 2017. 6.17 study -ing */
static inline bool gid_lt(kgid_t left, kgid_t right)
{
	return __kgid_val(left) < __kgid_val(right);
}

static inline bool uid_lte(kuid_t left, kuid_t right)
{
	return __kuid_val(left) <= __kuid_val(right);
}

static inline bool gid_lte(kgid_t left, kgid_t right)
{
	return __kgid_val(left) <= __kgid_val(right);
}

static inline bool uid_valid(kuid_t uid)
{
	return !uid_eq(uid, INVALID_UID);
}

static inline bool gid_valid(kgid_t gid)
{
	return !gid_eq(gid, INVALID_GID);
}

#ifdef CONFIG_USER_NS

extern kuid_t make_kuid(struct user_namespace *from, uid_t uid);
extern kgid_t make_kgid(struct user_namespace *from, gid_t gid);

extern uid_t from_kuid(struct user_namespace *to, kuid_t uid);
extern gid_t from_kgid(struct user_namespace *to, kgid_t gid);
extern uid_t from_kuid_munged(struct user_namespace *to, kuid_t uid);
extern gid_t from_kgid_munged(struct user_namespace *to, kgid_t gid);

static inline bool kuid_has_mapping(struct user_namespace *ns, kuid_t uid)
{
	return from_kuid(ns, uid) != (uid_t) -1;
}

static inline bool kgid_has_mapping(struct user_namespace *ns, kgid_t gid)
{
	return from_kgid(ns, gid) != (gid_t) -1;
}

#else
/*! 2017. 8.12 study -ing */
static inline kuid_t make_kuid(struct user_namespace *from, uid_t uid)
{
	return KUIDT_INIT(uid);
}

static inline kgid_t make_kgid(struct user_namespace *from, gid_t gid)
{
	return KGIDT_INIT(gid);
}
/*! 2017. 8.12 study -ing */
static inline uid_t from_kuid(struct user_namespace *to, kuid_t kuid)
{
	return __kuid_val(kuid);
}

static inline gid_t from_kgid(struct user_namespace *to, kgid_t kgid)
{
	return __kgid_val(kgid);
}
/*! 2017. 8.12 study -ing */
static inline uid_t from_kuid_munged(struct user_namespace *to, kuid_t kuid)
{
	uid_t uid = from_kuid(to, kuid);
	if (uid == (uid_t)-1)
		uid = overflowuid;
	return uid;
}

static inline gid_t from_kgid_munged(struct user_namespace *to, kgid_t kgid)
{
	gid_t gid = from_kgid(to, kgid);
	if (gid == (gid_t)-1)
		gid = overflowgid;
	return gid;
}

/*! 2017. 6.17 study -ing */
static inline bool kuid_has_mapping(struct user_namespace *ns, kuid_t uid)
{
	return true;
}
/*! 2017. 8.12 study -ing */
static inline bool kgid_has_mapping(struct user_namespace *ns, kgid_t gid)
{
	return true;
}

#endif /* CONFIG_USER_NS */

#endif /* _LINUX_UIDGID_H */
