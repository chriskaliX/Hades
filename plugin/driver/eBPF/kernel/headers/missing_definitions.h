#ifndef __TRACEE_MISSING_MACROS_H__
#define __TRACEE_MISSING_MACROS_H__

static inline bool
ipv6_addr_any(const struct in6_addr *a)
{
	return (a->in6_u.u6_addr32[0] | a->in6_u.u6_addr32[1] | a->in6_u.u6_addr32[2] | a->in6_u.u6_addr32[3]) == 0;
}