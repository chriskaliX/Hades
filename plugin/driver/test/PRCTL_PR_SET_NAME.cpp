#include <sys/prctl.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>

// g++ prctl.cpp -o prctl
int main(int argc, const char *argv[])
{
    printf("PRCTL: %d\n", PR_SET_NAME);
    prctl(PR_SET_NAME, "Test");
    return 0;
}