// v5: ctx-based gen calls with DB seeding
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
    anyf SetKey = dlsym(h, "SecSetInputKey");
    anyf gen_ont = dlsym(h, "gen_varlen_ontupw");
    anyf gen_vty = dlsym(h, "gen_varlen_vtyshpw");
    anyf gen_mgnt = dlsym(h, "gen_varlen_mgntpw");
    anyf gen_wlan = dlsym(h, "gen_varlen_wlanpw");
    anyf gen_omci = dlsym(h, "gen_omci_pwd");
    anyf getkey = dlsym(h, "SE_getKeyByName");
    anyf loadconf = dlsym(h, "SE_loadConfFile");
    anyf loadsec = dlsym(h, "SE_loadSecFile");
    anyf prehash = dlsym(h, "SecPreProcessGenHash");

    void *ctx = SecBlockInit();
    printf("ctx=%p\n", ctx);
    if (loadconf) printf("loadconf(/configs/se.conf)=%p\n", ((fn2)loadconf)("/configs/se.conf", 0));
    if (loadsec) printf("loadsec(/usr/etc/sec.key)=%p\n", ((fn2)loadsec)("/usr/etc/sec.key", 0));
    if (loadconf) printf("loadconf(/usr/etc/se.conf)=%p\n", ((fn2)loadconf)("/usr/etc/se.conf", 0));

    // seed DB values (candidate build-time chain values)
    ((fn3)SetKV)(ctx, "WLAN", "nSW6wc2[uofm");
    ((fn3)SetKV)(ctx, "VTYSH", "7lo:p9UzcjrS");
    ((fn3)SetKV)(ctx, "MGNT", serial);
    ((fn3)SetKV)(ctx, "SERIAL", serial);
    ((fn3)SetKV)(ctx, "serial", serial);
    ((fn3)SetKV)(ctx, "fw", "3TN00367LJLJ17");
    printf("DB seeded\n");

    if (getkey) {
        printf("--- keys ---\n");
        for (int i = 0; i < 20; i++) {
            char kn[16]; snprintf(kn, sizeof(kn), "key%d", i);
            char out[256]; memset(out, 0, sizeof(out));
            void *r = (void *)((fn3)getkey)(kn, out, (void *)(long)sizeof(out));
            if (r && out[0]) printf("key%d = \"%s\"\n", i, out);
        }
    }

    char out1[512], out2[512];
    struct { const char *name; anyf f; } gens[] = {
        {"ontupw", gen_ont}, {"vtyshpw", gen_vty}, {"mgntpw", gen_mgnt},
        {"wlanpw", gen_wlan}, {"omci", gen_omci},
    };
    for (unsigned g = 0; g < sizeof(gens)/sizeof(gens[0]); g++) {
        void *f = gens[g].f; if (!f) continue;
        // A: (ctx, len, salt, out1, out2)
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)f)(ctx, (void *)(long)12, (void *)"07", out1, out2);
        printf("%s A: ", gens[g].name); show_buf(out1, 40); printf(" | "); show_buf(out2, 40); printf("\n");
        // B: (ctx, serialhex, len, salt, out1)
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)f)(ctx, (void *)serialhex, (void *)(long)12, (void *)"07", out1);
        printf("%s B: ", gens[g].name); show_buf(out1, 40); printf("\n");
        // C: (ctx, serial, len, salt, out1)
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)f)(ctx, (void *)serial, (void *)(long)12, (void *)"07", out1);
        printf("%s C: ", gens[g].name); show_buf(out1, 40); printf("\n");
        // D: (ctx, serial, "07", out1, out2)
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)f)(ctx, (void *)serial, (void *)"07", out1, out2);
        printf("%s D: ", gens[g].name); show_buf(out1, 40); printf(" | "); show_buf(out2, 40); printf("\n");
        // E: (ctx, serialhex, "07", out1, out2)
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)f)(ctx, (void *)serialhex, (void *)"07", out1, out2);
        printf("%s E: ", gens[g].name); show_buf(out1, 40); printf(" | "); show_buf(out2, 40); printf("\n");
    }
    return 0;
}
