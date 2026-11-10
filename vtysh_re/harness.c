// v6: SecSetInputKV + SecPreProcessGenHash + gen — the missing preprocess step
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *(*fn5)(void *, void *, void *, void *, void *);
typedef void *(*fn3)(void *, void *, void *);
typedef void *(*fn2)(void *, void *);
typedef void *(*anyf)(void);

static void show_buf(const char *buf, int n) {
    for (int i = 0; i < n; i++) {
        unsigned char c = buf[i];
        if (c >= 0x20 && c < 0x7f) putchar(c);
        else printf("\\x%02x", c);
    }
}

int main(int argc, char **argv) {
    const char *serialhex = argc > 1 ? argv[1] : "41434c4c";
    const char *serial = argc > 2 ? argv[2] : "ALCLEB4CE6FC";
    void *h = dlopen("/usr/lib/libsec_engine.so", RTLD_NOW);
    if (!h) { printf("dlopen fail: %s\n", dlerror()); return 1; }
    anyf SecBlockInit = dlsym(h, "SecBlockInit");
    anyf SetKV = dlsym(h, "SecSetInputKV");
    anyf gen_ont = dlsym(h, "gen_varlen_ontupw");
    anyf gen_vty = dlsym(h, "gen_varlen_vtyshpw");
    anyf prehash = dlsym(h, "SecPreProcessGenHash");
    anyf loadconf = dlsym(h, "SE_loadConfFile");
    anyf loadsec = dlsym(h, "SE_loadSecFile");

    void *ctx = SecBlockInit();
    printf("ctx=%p\n", ctx);
    if (loadconf) printf("loadconf(/configs/se.conf)=%p\n", ((fn2)loadconf)("/configs/se.conf", 0));
    if (loadsec) printf("loadsec(/usr/etc/sec.key)=%p\n", ((fn2)loadsec)("/usr/etc/sec.key", 0));
    if (loadconf) printf("loadconf(/usr/etc/se.conf)=%p\n", ((fn2)loadconf)("/usr/etc/se.conf", 0));

    char out1[512], out2[512];
    const char *inputs[] = { serialhex, serial, "07", "VTYSH", "ONTUSER" };
    const char *inames[] = { "serialhex", "serial", "07", "VTYSH", "ONTUSER" };
    for (int k = 0; k < 5; k++) {
        // fresh ctx per input; FIRST KV value = the gen input (per SecPreProcessGenHash)
        void *c = SecBlockInit();
        ((fn3)SetKV)(c, "ONTUSER", inputs[k]);
        if (prehash) {
            void *r = (void *)((fn2)prehash)(c, 0);
            printf("[%s] prehash=%p\n", inames[k], r);
        }
        // A: (ctx, 12, "07", out1, out2)
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)gen_ont)(c, (void *)(long)12, (void *)"07", out1, out2);
        printf("[%s] ont A: ", inames[k]); show_buf(out1, 24); printf(" | "); show_buf(out2, 24); printf("\n");
        // B: (ctx, len, out1, out2, salt)
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)gen_ont)(c, (void *)(long)12, out1, out2, (void *)"07");
        printf("[%s] ont B: ", inames[k]); show_buf(out1, 24); printf("\n");
        // vtysh gen same way
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)gen_vty)(c, (void *)(long)12, (void *)"07", out1, out2);
        printf("[%s] vty A: ", inames[k]); show_buf(out1, 24); printf("\n");
    }
    return 0;
}
