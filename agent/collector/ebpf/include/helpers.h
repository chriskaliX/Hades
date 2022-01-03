static __always_inline int has_prefix(char *prefix, char *str, int n)
{
    #pragma unroll
    for (int i = 0; i < n; prefix++, str++, i++) {
        if (!*prefix)
            return 1;
        if (*prefix != *str) {
            return 0;
        }
    }
    // prefix is too long
    return 0;
}

static int has_prefix_new(const char *prefix, const char *str, int n)
{
    #pragma unroll
    for (int i = 0; i < n; i++) {
        if (prefix[i] != str[i])
            return 0;
    }
    return 1;
}