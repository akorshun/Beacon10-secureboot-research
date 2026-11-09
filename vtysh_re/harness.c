// Probe harness for libsec_engine.so on-device (aarch64, musl).
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *(*fn5)(void *, void *, void *, void *, void *);
typedef void *(*fn3)(void *, void *, void *);
typedef void *(*fn2)(void *, void *);
typedef void *(*anyf)(void);

static void show_buf(const char *tag, const char *buf, int n) {
    printf("%s: \"", tag);
    for (int i = 0; i < n; i++) {
        unsigned char c = buf[i];
        if (c >= 0x20 && c < 0x7f) putchar(c);
        else printf("\\x%02x", c);
    }
    printf("\"\n");
}

int main(int argc, char **argv) {
    const char *lib = argc > 1 ? argv[1] : "/usr/lib/libsec_engine.so";
    const char *input = argc > 2 ? argv[2] : "41434c4c";
    int pwlen = (argc > 3) ? atoi(argv[3]) : 12;
    const char *salt = argc > 4 ? argv[4] : "07";

    void *h = dlopen(lib, RTLD_NOW);
    if (!h) { printf("dlopen fail: %s\n", dlerror()); return 1; }
    printf("dlopen ok\n");

    anyf SecBlockInit = dlsym(h, "SecBlockInit");
    anyf gen_ont = dlsym(h, "gen_varlen_ontupw");
    anyf gen_vty = dlsym(h, "gen_varlen_vtyshpw");
    anyf gen_mgnt = dlsym(h, "gen_varlen_mgntpw");
    anyf gen_wlan = dlsym(h, "gen_varlen_wlanpw");
    anyf gen_omci = dlsym(h, "gen_omci_pwd");
    anyf getkey = dlsym(h, "SE_getKeyByName");
    anyf loadconf = dlsym(h, "SE_loadConfFile");
    anyf loadsec = dlsym(h, "SE_loadSecFile");

    if (SecBlockInit) {
        void *r = (void *)SecBlockInit();
        printf("SecBlockInit = %p\n", r);
    }
    if (loadsec) {
        void *r = (void *)((fn2)loadsec)("/usr/etc/sec.key", 0);
        printf("SE_loadSecFile(/usr/etc/sec.key) = %p\n", r);
    }
    if (loadconf) {
        void *r = (void *)((fn2)loadconf)("/usr/etc/se.conf", 0);
        printf("SE_loadConfFile(/usr/etc/se.conf) = %p\n", r);
    }

    if (getkey) {
        printf("--- keys after init ---\n");
        for (int i = 0; i < 20; i++) {
            char kn[16]; snprintf(kn, sizeof(kn), "key%d", i);
            char out[256]; memset(out, 0, sizeof(out));
            void *r = (void *)((fn3)getkey)(kn, out, (void *)(long)sizeof(out));
            if (r && out[0]) printf("key%d = \"%s\"\n", i, out);
        }
    }

    char out1[512], out2[512];
    printf("--- gen permutations (input=%s len=%d salt=%s) ---\n", input, pwlen, salt);
    struct { const char *name; anyf f; } gens[] = {
        {"ontupw", gen_ont}, {"vtyshpw", gen_vty}, {"mgntpw", gen_mgnt},
        {"wlanpw", gen_wlan}, {"omci", gen_omci},
    };
    for (unsigned g = 0; g < sizeof(gens)/sizeof(gens[0]); g++) {
        void *f = gens[g].f; if (!f) continue;
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)f)((void *)input, (void *)(long)pwlen, (void *)salt, out1, out2);
        printf("%s p1: out1: ", gens[g].name); show_buf("", out1, 40);
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)f)(out1, (void *)(long)pwlen, (void *)salt, (void *)input, out2);
        printf("%s p2: out1: ", gens[g].name); show_buf("", out1, 40);
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)f)((void *)input, (void *)salt, (void *)(long)pwlen, out1, out2);
        printf("%s p3: out1: ", gens[g].name); show_buf("", out1, 40);
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)f)((void *)input, (void *)(long)pwlen, out1, out2, (void *)salt);
        printf("%s p4: out1: ", gens[g].name); show_buf("", out1, 40);
    }
    return 0;
}
