#ifndef __HELPERS_H
#define __HELPERS_H
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

#endif //__HELPERS_H
