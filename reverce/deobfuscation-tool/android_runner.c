#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: runner library input\n"); return 2; }
    char *end; errno=0; long n=strtol(argv[2], &end, 10);
    if (errno || *end || n<INT32_MIN || n>INT32_MAX) return 2;
    void *h=dlopen(argv[1], RTLD_NOW); if (!h) { fprintf(stderr, "%s\n", dlerror()); return 3; }
    int32_t (*fn)(int32_t)=(int32_t (*)(int32_t))dlsym(h,"lesson_score");
    if (!fn) { fprintf(stderr, "%s\n", dlerror()); dlclose(h); return 4; }
    printf("RESULT:%d\n", fn((int32_t)n)); dlclose(h); return 0;
}
