#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    char *end;
    errno = 0;
    long value = strtol(argv[2], &end, 10);
    if (errno || *end || value < INT32_MIN || value > INT32_MAX) return 2;
    void *library = dlopen(argv[1], RTLD_NOW);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 3; }
    int32_t (*score)(int32_t) = (int32_t (*)(int32_t))dlsym(library, "route_score");
    if (!score) { fprintf(stderr, "%s\n", dlerror()); dlclose(library); return 4; }
    printf("RESULT:%d\n", score((int32_t)value));
    dlclose(library);
    return 0;
}
