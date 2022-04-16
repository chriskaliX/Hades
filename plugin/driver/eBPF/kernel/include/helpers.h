#ifndef __HELPERS_H
#define __HELPERS_H
#ifndef CORE
#include <linux/cred.h>
#include <linux/uidgid.h>
#else
#include <vmlinux.h>
#include <missing_definitions.h>
#endif

static __inline int has_prefix(char *prefix, char *str, int n)
{
    int i;
    #pragma unroll
    for (i = 0; i < n; prefix++, str++, i++) {
        if (!*prefix)
            return 1;
        if (*prefix != *str) {
            return 0;
        }
    }
    // prefix is too long
    return 0;
}

static int prefix(char *prefix, char *str, int n)
{
    int i;
    #pragma unroll
    for (i = 0; i < n; i++) {
        if (prefix[i] != str[i])
            return 0;
    }
    return 1;
}

// All down here are mainly copied from Linux Source Code.
// Check part is from Elkeid, but I need think twice.
#define KUIDT(value) (const kuid_t) { value }
#define KGIDT(value) (const kgid_t) { value }
#define ROOT_UID KUIDT(0)
#define ROOT_GID KGIDT(0)

static inline uid_t hades_uid_val(kuid_t uid)
{
    return uid.val;
}

static inline bool hades_uid_eq(kuid_t left, kuid_t right)
{
    return hades_uid_val(left) == hades_uid_val(right);
}

static inline gid_t hades_gid_val(kgid_t gid)
{
    return gid.val;
}

static inline bool hades_gid_eq(kgid_t left, kgid_t right)
{
    return hades_gid_val(left) == hades_gid_val(right);
}

// In Elkeid, in compare like this:
// Firstly, any of cred field is zero is considered as privilege escalation prequisite.
// Secondly, any field changes
// And except the all root id
// But I think... it's somehow weird.
static __always_inline u8 check_cred(const struct cred *current_cred, const struct cred *parent_cred)
{
    if (hades_uid_eq(READ_KERN(current_cred->uid), ROOT_UID) ||
        hades_gid_eq(READ_KERN(current_cred->gid), ROOT_GID) ||
        hades_uid_eq(READ_KERN(current_cred->suid), ROOT_UID) ||
        hades_gid_eq(READ_KERN(current_cred->sgid), ROOT_GID) ||
        hades_uid_eq(READ_KERN(current_cred->euid), ROOT_UID) ||
        hades_gid_eq(READ_KERN(current_cred->egid), ROOT_GID) ||
        hades_uid_eq(READ_KERN(current_cred->fsuid), ROOT_UID) ||
        hades_gid_eq(READ_KERN(current_cred->fsgid), ROOT_GID))
        if (!hades_uid_eq(READ_KERN(current_cred->uid), READ_KERN(parent_cred->uid)) ||
            !hades_gid_eq(READ_KERN(current_cred->gid), READ_KERN(parent_cred->gid)) ||
            !hades_uid_eq(READ_KERN(current_cred->suid), READ_KERN(parent_cred->suid)) ||
            !hades_gid_eq(READ_KERN(current_cred->sgid), READ_KERN(parent_cred->sgid)) ||
            !hades_uid_eq(READ_KERN(current_cred->euid), READ_KERN(parent_cred->euid)) ||
            !hades_gid_eq(READ_KERN(current_cred->egid), READ_KERN(parent_cred->egid)) ||
            !hades_uid_eq(READ_KERN(current_cred->fsuid), READ_KERN(parent_cred->fsuid)) ||
            !hades_gid_eq(READ_KERN(current_cred->fsgid), READ_KERN(parent_cred->fsgid)))
            if (!(hades_uid_eq(READ_KERN(parent_cred->uid), ROOT_UID) &&
                  hades_gid_eq(READ_KERN(parent_cred->gid), ROOT_GID) &&
                  hades_uid_eq(READ_KERN(parent_cred->suid), ROOT_UID) &&
                  hades_gid_eq(READ_KERN(parent_cred->sgid), ROOT_GID) &&
                  hades_uid_eq(READ_KERN(parent_cred->euid), ROOT_UID) &&
                  hades_gid_eq(READ_KERN(parent_cred->egid), ROOT_GID) &&
                  hades_uid_eq(READ_KERN(parent_cred->fsuid), ROOT_UID) &&
                  hades_gid_eq(READ_KERN(parent_cred->fsgid), ROOT_GID)))
                return 1;
    return 0;
}

#endif //__HELPERS_H
