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
    return 0;
}

static __always_inline int prefix(char *prefix, char *str, int n)
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
#define KUIDT(value)                                                           \
    (const kuid_t)                                                             \
    {                                                                          \
        value                                                                  \
    }
#define KGIDT(value)                                                           \
    (const kgid_t)                                                             \
    {                                                                          \
        value                                                                  \
    }
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

static __always_inline bool hades_cred_check_is_root(const struct cred *cred)
{
    kuid_t kuid;
    // kuid check
    kuid = READ_KERN(cred->uid);
    if (hades_uid_eq(kuid, ROOT_UID))
        return true;
    kuid = READ_KERN(cred->suid);
    if (hades_uid_eq(kuid, ROOT_UID))
        return true;
    kuid = READ_KERN(cred->euid);
    if (hades_uid_eq(kuid, ROOT_UID))
        return true;
    kuid = READ_KERN(cred->fsuid);
    if (hades_uid_eq(kuid, ROOT_UID))
        return true;
    // kgid check
    kgid_t kgid;
    kgid = READ_KERN(cred->gid);
    if (hades_gid_eq(kgid, ROOT_GID))
        return true;
    kgid = READ_KERN(cred->sgid);
    if (hades_gid_eq(kgid, ROOT_GID))
        return true;
    kgid = READ_KERN(cred->egid);
    if (hades_gid_eq(kgid, ROOT_GID))
        return true;
    kgid = READ_KERN(cred->fsgid);
    if (hades_gid_eq(kgid, ROOT_GID))
        return true;
    return false;
}

static __always_inline bool
hades_cred_check_is_changed(const struct cred *current_cred,
                            const struct cred *parent_cred)
{
    kuid_t kuid_current;
    kuid_t kuid_parent;
    kuid_current = READ_KERN(current_cred->uid);
    kuid_parent = READ_KERN(parent_cred->uid);
    if (!hades_uid_eq(kuid_current, kuid_parent))
        return true;
    kuid_current = READ_KERN(current_cred->suid);
    kuid_parent = READ_KERN(parent_cred->suid);
    if (!hades_uid_eq(kuid_current, kuid_parent))
        return true;
    kuid_current = READ_KERN(current_cred->euid);
    kuid_parent = READ_KERN(parent_cred->euid);
    if (!hades_uid_eq(kuid_current, kuid_parent))
        return true;
    kuid_current = READ_KERN(current_cred->fsuid);
    kuid_parent = READ_KERN(parent_cred->fsuid);
    if (!hades_uid_eq(kuid_current, kuid_parent))
        return true;
    kgid_t kgid_current;
    kgid_t kgid_parent;
    kgid_current = READ_KERN(current_cred->gid);
    kgid_parent = READ_KERN(parent_cred->gid);
    if (!hades_gid_eq(kgid_current, kgid_parent))
        return true;
    kgid_current = READ_KERN(current_cred->sgid);
    kgid_parent = READ_KERN(parent_cred->sgid);
    if (!hades_gid_eq(kgid_current, kgid_parent))
        return true;
    kgid_current = READ_KERN(current_cred->egid);
    kgid_parent = READ_KERN(parent_cred->egid);
    if (!hades_gid_eq(kgid_current, kgid_parent))
        return true;
    kgid_current = READ_KERN(current_cred->fsgid);
    kgid_parent = READ_KERN(parent_cred->fsgid);
    if (!hades_gid_eq(kgid_current, kgid_parent))
        return true;
    return false;
}

static __always_inline bool
hades_cred_check_is_all_root(const struct cred *cred)
{
    kuid_t kuid;
    // kuid check
    kuid = READ_KERN(cred->uid);
    if (!hades_uid_eq(kuid, ROOT_UID))
        return false;
    kuid = READ_KERN(cred->suid);
    if (!hades_uid_eq(kuid, ROOT_UID))
        return false;
    kuid = READ_KERN(cred->euid);
    if (!hades_uid_eq(kuid, ROOT_UID))
        return false;
    kuid = READ_KERN(cred->fsuid);
    if (!hades_uid_eq(kuid, ROOT_UID))
        return false;
    // kgid check
    kgid_t kgid;
    kgid = READ_KERN(cred->gid);
    if (!hades_gid_eq(kgid, ROOT_GID))
        return false;
    kgid = READ_KERN(cred->sgid);
    if (!hades_gid_eq(kgid, ROOT_GID))
        return false;
    kgid = READ_KERN(cred->egid);
    if (!hades_gid_eq(kgid, ROOT_GID))
        return false;
    kgid = READ_KERN(cred->fsgid);
    if (!hades_gid_eq(kgid, ROOT_GID))
        return false;
    return true;
}

// In Elkeid, in compare like this:
// Firstly, any of cred field is zero is considered as privilege escalation prequisite.
// Secondly, any field changes
// And except the all root id
// But I think... it's somehow weird.
// 2022-04-17: yes! it's here that make the eBPF program exceeds the limit of 512 bytes
// The reference we metioned before shows that the bpf_core_read way READ_KERN
// may cause the program stack spillage, but the reason is unclear in portable-code
// Because of this, we need some modification of this. And know optimizing is done!
static __always_inline u8 check_cred(const struct cred *current_cred,
                                     const struct cred *parent_cred)
{
    // record only if the cred is know
    if (!hades_cred_check_is_root(current_cred))
        return 0;
    // record only if the cred changes
    if (!hades_cred_check_is_changed(current_cred, parent_cred))
        return 0;
    // skip if the parent is root.
    // Example: root->su www->...
    if (hades_cred_check_is_all_root(parent_cred))
        return 0;
    return 1;
}

#endif //__HELPERS_H
