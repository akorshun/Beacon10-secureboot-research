// v7: full engine init incl. sedb.conf + ctx gens
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *(*fn5)(void *, void *, void *, void *, void *);
typedef void *(*fn3)(void *, void *, void *);
typedef void *(*fn2)(void *, void *);
typedef void *(*anyf)(void);

static void show_buf(const char *buf, int n) {
    int i;
    for (i = 0; i < n; i++) {
        unsigned char c = buf[i];
        if (c >= 0x20 && c < 0x7f) putchar(c);
        else printf(".");
    }
}

int main(int argc, char **argv) {
    void *h = dlopen("/usr/lib/libsec_engine.so", RTLD_NOW);
    if (!h) { printf("dlopen fail: %s\n", dlerror()); return 1; }
    anyf SecBlockInit = dlsym(h, "SecBlockInit");
    anyf SetKV = dlsym(h, "SecSetInputKV");
    anyf gen_ont = dlsym(h, "gen_varlen_ontupw");
    anyf gen_vty = dlsym(h, "gen_varlen_vtyshpw");
    anyf prehash = dlsym(h, "SecPreProcessGenHash");
    anyf loadconf = dlsym(h, "SE_loadConfFile");
    anyf loadsec = dlsym(h, "SE_loadSecFile");
    anyf getkey = dlsym(h, "SE_getKeyByName");

    void *ctx = SecBlockInit();
    printf("ctx=%p\n", ctx);
    printf("loadconf(/configs/se.conf)=%p\n", ((fn2)loadconf)("/configs/se.conf", 0));
    printf("loadsec(/configs/sedb.conf)=%p\n", ((fn2)loadsec)("/configs/sedb.conf", 0));
    printf("loadsec(/usr/etc/sec.key)=%p\n", ((fn2)loadsec)("/usr/etc/sec.key", 0));
    printf("loadconf(/usr/etc/se.conf)=%p\n", ((fn2)loadconf)("/usr/etc/se.conf", 0));

    printf("--- keys ---\n");
    for (int i = 0; i < 20; i++) {
        char kn[16]; snprintf(kn, sizeof(kn), "key%d", i);
        char out[256]; memset(out, 0, sizeof(out));
        void *r = (void *)((fn3)getkey)(kn, out, (void *)(long)sizeof(out));
        if (r && out[0]) printf("key%d = \"%s\"
", i, out);
    }

    char out1[512], out2[512];
    void *gens[5]; const char *gnames[5];
    gens[0] = dlsym(h, "gen_varlen_ontupw");  gnames[0] = "ont";
    gens[1] = dlsym(h, "gen_varlen_vtyshpw"); gnames[1] = "vty";
    gens[2] = dlsym(h, "gen_varlen_mgntpw");  gnames[2] = "mgnt";
    gens[3] = dlsym(h, "gen_varlen_wlanpw");  gnames[3] = "wlan";
    gens[4] = dlsym(h, "gen_omci_pwd");       gnames[4] = "omci";
    for (int g = 0; g < 5; g++) {
        if (!gens[g]) continue;
        memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
        ((fn5)gens[g])(ctx, (void *)(long)12, (void *)"07", out1, out2);
        printf("%s A: \"", gnames[g]); show_buf(out1, 32); printf("\" | \""); show_buf(out2, 32); printf("\"
");
    }
    return 0;
}
