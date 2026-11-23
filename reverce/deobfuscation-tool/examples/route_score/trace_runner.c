#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
    void *library = dlopen("/data/local/tmp/libroute_fla.so", RTLD_NOW);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 1; }
    int32_t (*score)(int32_t) = (int32_t (*)(int32_t))dlsym(library, "route_score");
    if (!score) { fprintf(stderr, "%s\n", dlerror()); return 1; }
    const int32_t inputs[] = {0, 1, 2, 5, 10, 30, -5, -33, 127};
    printf("PID=%ld\n", (long)getpid());
    fflush(stdout);
    getchar();
    for (unsigned i = 0; i < sizeof(inputs) / sizeof(inputs[0]); ++i)
        printf("RESULT:%d:%d\n", inputs[i], score(inputs[i]));
    fflush(stdout);
    dlclose(library);
    return 0;
}
