// Probe harness for libsec_engine.so on-device (aarch64, musl).
// Tries multiple calling conventions of the gen_varlen_* password generators
// and dumps engine state (keys, conf values) to find the ONTUSER password.
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef void *(*anyf)(void);

static void dump_hex(const char *tag, const unsigned char *p, int n) {
    printf("%s: ", tag);
    for (int i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

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
    const char *input = argc > 2 ? argv[2] : "41434c4c";   // hex("ALCL")
    int pwlen = (argc > 3) ? atoi(argv[3]) : 12;
    const char *salt = argc > 4 ? argv[4] : "07";

    void *h = dlopen(lib, RTLD_NOW);
    if (!h) { printf("dlopen fail: %s\n", dlerror()); return 1; }
    printf("dlopen ok\n");

    anyf SecBlockInit = dlsym(h, "SecBlockInit");
    anyf gen_ont = dlsym(h, "gen_varlen_ontupw");
    anyf gen_vty = dlsym(h, "gen_varlen_vtyshpw");
    anyf gen_mgnt = dlsym(h, "gen_varlen_mgntpw");
    anyf gen_mgnt_c = dlsym(h, "gen_varlen_mgntpw_customize");
    anyf gen_wlan = dlsym(h, "gen_varlen_wlanpw");
    anyf gen_omci = dlsym(h, "gen_omci_pwd");
    anyf getkey = dlsym(h, "SE_getKeyByName");
    anyf loadconf = dlsym(h, "SE_loadConfFile");
    anyf loadsec = dlsym(h, "SE_loadSecFile");
    anyf getconf = dlsym(h, "SE_getConfValue");
    anyf auth = dlsym(h, "SE_passwd_db_auth_ex");
    anyf prehash = dlsym(h, "SecPreProcessGenHash");
    anyf setkv = dlsym(h, "SecSetInputKV");
    anyf setkey = dlsym(h, "SecSetInputKey");
    printf("syms: init=%p ont=%p vty=%p mgnt=%p wlan=%p omci=%p getkey=%p loadconf=%p loadsec=%p getconf=%p auth=%p setkv=%p setkey=%p\n",
        SecBlockInit, gen_ont, gen_vty, gen_mgnt, gen_wlan, gen_omci, getkey, loadconf, loadsec, getconf, auth, setkv, setkey);

    if (loadconf) {
        void *r = (void *)loadconf("/usr/etc/se.conf");
        printf("SE_loadConfFile(/usr/etc/se.conf) = %p\n", r);
    }
    if (loadsec) {
        void *r = (void *)loadsec("/usr/etc/se.conf");
        printf("SE_loadSecFile(/usr/etc/se.conf) = %p\n", r);
    }

    // Dump derived keys by name: key0..key19
    if (getkey) {
        for (int i = 0; i < 20; i++) {
            char kn[16]; snprintf(kn, sizeof(kn), "key%d", i);
            char out[256]; memset(out, 0, sizeof(out));
            void *r = (void *)((anyf)getkey)(kn, out, sizeof(out));
            if (r && out[0]) printf("key%d = \"%s\"\n", i, out);
        }
    }

    char out1[512], out2[512];
    memset(out1, 0x41, sizeof(out1)); memset(out2, 0x42, sizeof(out2));

    // Calling convention guess A: gen(out, len, saltlen?, in, in2)
    if (gen_ont) {
        printf("--- gen_varlen_ontupw permutations (input=%s len=%d salt=%s) ---\n", input, pwlen, salt);
        struct { const char *name; void *f; } gens[] = {
            {"ontupw", gen_ont}, {"vtyshpw", gen_vty}, {"mgntpw", gen_mgnt},
            {"mgntpw_c", gen_mgnt_c}, {"wlanpw", gen_wlan}, {"omci", gen_omci},
        };
        for (unsigned g = 0; g < sizeof(gens)/sizeof(gens[0]); g++) {
            void *f = gens[g].f; if (!f) continue;
            // perm 1: (in, len, salt, out1, out2)
            memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
            ((anyf)f)((void *)input, (void *)(long)pwlen, (void *)salt, out1, out2);
            printf("%s p1: in->out1: ", gens[g].name); show_buf("", out1, 40); printf("  out2: "); show_buf("", out2, 40);
            // perm 2: (out, len, salt, in, in2)
            memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
            ((anyf)f)(out1, (void *)(long)pwlen, (void *)salt, (void *)input, out2);
            printf("%s p2: out1: ", gens[g].name); show_buf("", out1, 40); printf("  out2: "); show_buf("", out2, 40);
            // perm 3: (in, salt, len, out1, out2)
            memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
            ((anyf)f)((void *)input, (void *)salt, (void *)(long)pwlen, out1, out2);
            printf("%s p3: out1: ", gens[g].name); show_buf("", out1, 40); printf("  out2: "); show_buf("", out2, 40);
            // perm 4: (in, len, out1, out2, salt)
            memset(out1, 0, sizeof(out1)); memset(out2, 0, sizeof(out2));
            ((anyf)f)((void *)input, (void *)(long)pwlen, out1, out2, (void *)salt);
            printf("%s p4: out1: ", gens[g].name); show_buf("", out1, 40); printf("  out2: "); show_buf("", out2, 40);
        }
    }
    return 0;
}
