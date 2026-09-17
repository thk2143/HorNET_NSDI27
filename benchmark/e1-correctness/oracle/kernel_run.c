// kernel_run.c — run one XDP object in the kernel with BPF_PROG_TEST_RUN.
//
// The kernel oracle of E1's cases: benchmark/e1-correctness/oracle/record.py
// drives it (under sudo, the only privileged step anywhere in E1) and turns
// what it prints into kernel.json, which the ordinary unprivileged E1 run
// compares hornet against.
//
// Output is line-oriented so neither side needs a JSON parser:
//
//   version libbpf <major>.<minor> kernel <release>
//   cycle <n>
//   load ok | load rejected <errno>        the verifier log goes to stderr
//   run retval <u32> errno <errno> size_out <bytes>
//   pkt <hex>                              with --data-out
//   map <name> <keyhex> <valhex>           with --dump / --dump-all
//   map <name> <keyhex> absent
//   bss <hex>                              with --dump-bss: the whole .bss
//   warn <what>
//   end
//
// Every cycle opens, loads, seeds, runs, dumps and closes the object again,
// so each one starts from freshly created maps; record.py compares cycles to
// catch a nondeterministic program. Map keys and values are the raw bytes in
// memory order. A per-CPU map is seeded with the same value on every CPU and
// read back at --cpu, the CPU the process is pinned to -- the one test_run
// executes on -- with a warning if any other CPU's slot moved.

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAX_ITEMS 64
#define PKT_MAX   4096
#define OUT_MAX   (PKT_MAX + 512)          /* bpf_xdp_adjust_head can grow the frame */

struct blob { unsigned char *b; size_t n; };
struct seed { const char *map; struct blob key, val; };
struct dump { const char *map; struct blob key; int all; };
struct tail { char *path, *prog, *map; int slot; };

static struct {
    const char *obj, *prog;
    int cpu, cycles;
    struct tail tails[MAX_ITEMS]; int ntails;
    struct seed seeds[MAX_ITEMS]; int nseeds;
    struct dump dumps[MAX_ITEMS]; int ndumps;
    struct blob pkt;
    int have_ctx; unsigned ifindex, rxq;
    int dump_bss, data_out;
} opt = { .cpu = 0, .cycles = 1 };

static void die(const char *fmt, ...)
{
    va_list ap;
    printf("error ");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    exit(2);
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    c |= 0x20;
    return (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
}

static struct blob unhex(const char *s)
{
    struct blob out = { calloc(1, strlen(s) / 2 + 1), 0 };
    int hi = -1;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    for (; *s; s++) {
        if (*s == ' ' || *s == '_')
            continue;
        int v = hexval((unsigned char)*s);
        if (v < 0)
            die("bad hex digit '%c'", *s);
        if (hi < 0) {
            hi = v;
        } else {
            out.b[out.n++] = (unsigned char)(hi << 4 | v);
            hi = -1;
        }
    }
    if (hi >= 0)
        die("odd number of hex digits");
    return out;
}

static void print_hex(const unsigned char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", b[i]);
}

// ── maps ─────────────────────────────────────────────────────────────────────

static int is_percpu(enum bpf_map_type t)
{
    return t == BPF_MAP_TYPE_PERCPU_HASH || t == BPF_MAP_TYPE_PERCPU_ARRAY ||
           t == BPF_MAP_TYPE_LRU_PERCPU_HASH ||
           t == BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE;
}

// The buffer a lookup or update on this map takes, and one CPU's slot in it.
static size_t value_buf(const struct bpf_map *m, size_t *stride)
{
    size_t vsz = bpf_map__value_size(m);
    if (!is_percpu(bpf_map__type(m))) {
        *stride = vsz;
        return vsz;
    }
    *stride = (vsz + 7) & ~(size_t)7;
    return *stride * (size_t)libbpf_num_possible_cpus();
}

// By name; an internal map (".bss") also by the suffix libbpf gives it.
static struct bpf_map *find_map(struct bpf_object *obj, const char *name)
{
    struct bpf_map *m = bpf_object__find_map_by_name(obj, name);
    if (m)
        return m;
    bpf_object__for_each_map(m, obj) {
        const char *n = bpf_map__name(m);
        size_t ln = strlen(n), lk = strlen(name);
        if (name[0] == '.' && ln >= lk && !strcmp(n + ln - lk, name))
            return m;
    }
    return NULL;
}

static const struct blob *seeded(const char *map, const unsigned char *key, size_t ksz)
{
    for (int i = 0; i < opt.nseeds; i++)
        if (!strcmp(opt.seeds[i].map, map) && opt.seeds[i].key.n == ksz &&
            !memcmp(opt.seeds[i].key.b, key, ksz))
            return &opt.seeds[i].val;
    return NULL;
}

static void seed(struct bpf_object *obj, const struct seed *s)
{
    struct bpf_map *m = find_map(obj, s->map);
    if (!m)
        die("no map %s in %s", s->map, opt.obj);
    if (s->key.n != bpf_map__key_size(m) || s->val.n != bpf_map__value_size(m))
        die("map %s: seed is key %zu / value %zu bytes, map is %u / %u", s->map,
            s->key.n, s->val.n, bpf_map__key_size(m), bpf_map__value_size(m));
    size_t stride, n = value_buf(m, &stride);
    unsigned char *buf = calloc(1, n);
    for (size_t off = 0; off < n; off += stride)
        memcpy(buf + off, s->val.b, s->val.n);
    if (bpf_map_update_elem(bpf_map__fd(m), s->key.b, buf, BPF_ANY))
        die("map %s: update failed: %s", s->map, strerror(errno));
    free(buf);
}

static void dump_key(const struct bpf_map *m, const char *name, const unsigned char *key)
{
    size_t ksz = bpf_map__key_size(m), vsz = bpf_map__value_size(m), stride;
    size_t n = value_buf(m, &stride);
    unsigned char *buf = calloc(1, n);
    printf("map %s ", name);
    print_hex(key, ksz);
    if (bpf_map_lookup_elem(bpf_map__fd(m), key, buf)) {
        printf(" absent\n");
        free(buf);
        return;
    }
    printf(" ");
    print_hex(buf + (size_t)opt.cpu * stride, vsz);
    printf("\n");
    if (stride != n) {
        const struct blob *was = seeded(name, key, ksz);
        for (size_t off = 0; off < n; off += stride) {
            if (off == (size_t)opt.cpu * stride)
                continue;
            int moved = 0;
            for (size_t i = 0; i < vsz && !moved; i++)
                moved = buf[off + i] != (was ? was->b[i] : 0);
            if (moved) {
                printf("warn percpu-other-cpu-changed %s ", name);
                print_hex(key, ksz);
                printf("\n");
                break;
            }
        }
    }
    free(buf);
}

static void dump_all(const struct bpf_map *m, const char *name)
{
    size_t ksz = bpf_map__key_size(m);
    unsigned char *cur = calloc(1, ksz), *next = calloc(1, ksz);
    int first = 1;
    while (bpf_map_get_next_key(bpf_map__fd(m), first ? NULL : cur, next) == 0) {
        dump_key(m, name, next);
        memcpy(cur, next, ksz);
        first = 0;
    }
    free(cur);
    free(next);
}

// ── one cycle ────────────────────────────────────────────────────────────────

static struct bpf_map *only_prog_array(struct bpf_object *obj)
{
    struct bpf_map *m, *found = NULL;
    bpf_object__for_each_map(m, obj) {
        if (bpf_map__type(m) != BPF_MAP_TYPE_PROG_ARRAY)
            continue;
        if (found)
            die("%s has more than one PROG_ARRAY: name one in --tail", opt.obj);
        found = m;
    }
    if (!found)
        die("%s has no PROG_ARRAY for --tail", opt.obj);
    return found;
}

// Load one tail callee and put it in its caller's program array. Maps the two
// objects both declare are shared by name, as one loader would share them;
// internal maps (.bss, .rodata) stay private to each object.
static struct bpf_object *load_tail(struct bpf_object *caller, const struct tail *t)
{
    struct bpf_object *co = bpf_object__open_file(t->path, NULL);
    if (!co)
        die("cannot open tail %s: %s", t->path, strerror(errno));
    struct bpf_map *cm;
    bpf_object__for_each_map(cm, co) {
        const char *n = bpf_map__name(cm);
        if (strchr(n, '.'))
            continue;
        struct bpf_map *pm = bpf_object__find_map_by_name(caller, n);
        if (pm && bpf_map__reuse_fd(cm, bpf_map__fd(pm)))
            die("tail %s: cannot share map %s", t->path, n);
    }
    if (bpf_object__load(co)) {
        printf("load rejected %d tail %s\n", errno, t->path);
        bpf_object__close(co);
        return NULL;
    }
    struct bpf_program *cp = bpf_object__find_program_by_name(co, t->prog);
    if (!cp)
        die("tail %s has no program %s", t->path, t->prog);
    struct bpf_map *pa = t->map ? find_map(caller, t->map) : only_prog_array(caller);
    if (!pa)
        die("no program array %s in %s", t->map, opt.obj);
    int slot = t->slot, fd = bpf_program__fd(cp);
    if (bpf_map_update_elem(bpf_map__fd(pa), &slot, &fd, BPF_ANY))
        die("cannot put %s at slot %d: %s", t->prog, slot, strerror(errno));
    return co;
}

static void cycle(int n)
{
    printf("cycle %d\n", n);
    struct bpf_object *obj = bpf_object__open_file(opt.obj, NULL);
    if (!obj)
        die("cannot open %s: %s", opt.obj, strerror(errno));
    struct bpf_program *p, *prog = NULL;
    bpf_object__for_each_program(p, obj) {
        int mine = !strcmp(bpf_program__name(p), opt.prog);
        bpf_program__set_autoload(p, mine);
        if (mine)
            prog = p;
    }
    if (!prog)
        die("%s has no program %s", opt.obj, opt.prog);
    bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

    if (bpf_object__load(obj)) {
        printf("load rejected %d\nend\n", errno);
        bpf_object__close(obj);
        return;
    }
    printf("load ok\n");
    for (int i = 0; i < opt.nseeds; i++)
        seed(obj, &opt.seeds[i]);

    struct bpf_object *callees[MAX_ITEMS] = { 0 };
    for (int i = 0; i < opt.ntails; i++) {
        callees[i] = load_tail(obj, &opt.tails[i]);
        if (!callees[i])
            goto out;
    }

    unsigned char out[OUT_MAX];
    struct xdp_md ctx_in = {
        .data_end = (__u32)opt.pkt.n,
        .ingress_ifindex = opt.ifindex,
        .rx_queue_index = opt.rxq,
    };
    LIBBPF_OPTS(bpf_test_run_opts, run,
        .data_in = opt.pkt.b,
        .data_size_in = (__u32)opt.pkt.n,
        .data_out = out,
        .data_size_out = sizeof out,
        .repeat = 1,
    );
    if (opt.have_ctx) {
        run.ctx_in = &ctx_in;
        run.ctx_size_in = sizeof ctx_in;
    }
    int err = bpf_prog_test_run_opts(bpf_program__fd(prog), &run);
    printf("run retval %u errno %d size_out %u\n", run.retval, err ? errno : 0,
           run.data_size_out);
    if (err)
        goto out;

    if (opt.data_out) {
        printf("pkt ");
        print_hex(out, run.data_size_out);
        printf("\n");
    }
    for (int i = 0; i < opt.ndumps; i++) {
        struct bpf_map *m = find_map(obj, opt.dumps[i].map);
        if (!m)
            die("no map %s to dump", opt.dumps[i].map);
        if (opt.dumps[i].all) {
            dump_all(m, opt.dumps[i].map);
            continue;
        }
        if (opt.dumps[i].key.n != bpf_map__key_size(m))
            die("map %s: dump key is %zu bytes, map wants %u", opt.dumps[i].map,
                opt.dumps[i].key.n, bpf_map__key_size(m));
        dump_key(m, opt.dumps[i].map, opt.dumps[i].key.b);
    }
    if (opt.dump_bss) {
        struct bpf_map *m = find_map(obj, ".bss");
        if (!m) {
            printf("bss \n");
        } else {
            size_t stride, sz = value_buf(m, &stride);
            unsigned char *buf = calloc(1, sz);
            int zero = 0;
            if (bpf_map_lookup_elem(bpf_map__fd(m), &zero, buf))
                die(".bss lookup failed: %s", strerror(errno));
            printf("bss ");
            print_hex(buf, sz);
            printf("\n");
            free(buf);
        }
    }
out:
    printf("end\n");
    for (int i = 0; i < opt.ntails; i++)
        if (callees[i])
            bpf_object__close(callees[i]);
    bpf_object__close(obj);
}

// ── arguments ────────────────────────────────────────────────────────────────

// PATH:PROG@[MAP/]SLOT, the same shape as hornet's --tail.
static struct tail parse_tail(char *s)
{
    struct tail t = { 0 };
    char *at = strrchr(s, '@'), *colon = strrchr(s, ':');
    if (!at || !colon || colon > at)
        die("--tail wants PATH:PROG@[MAP/]SLOT, got %s", s);
    *at = *colon = '\0';
    t.path = s;
    t.prog = colon + 1;
    char *slash = strchr(at + 1, '/');
    if (slash) {
        *slash = '\0';
        t.map = at + 1;
        t.slot = atoi(slash + 1);
    } else {
        t.slot = atoi(at + 1);
    }
    return t;
}

static void need(int i, int argc, int k, const char *flag)
{
    if (i + k >= argc)
        die("%s needs %d argument(s)", flag, k);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--version")) {
            struct utsname u;
            uname(&u);
            printf("version libbpf %u.%u kernel %s\n", libbpf_major_version(),
                   libbpf_minor_version(), u.release);
            return 0;
        } else if (!strcmp(a, "--obj")) {
            need(i, argc, 1, a); opt.obj = argv[++i];
        } else if (!strcmp(a, "--prog")) {
            need(i, argc, 1, a); opt.prog = argv[++i];
        } else if (!strcmp(a, "--cpu")) {
            need(i, argc, 1, a); opt.cpu = atoi(argv[++i]);
        } else if (!strcmp(a, "--cycles")) {
            need(i, argc, 1, a); opt.cycles = atoi(argv[++i]);
        } else if (!strcmp(a, "--tail")) {
            need(i, argc, 1, a);
            if (opt.ntails == MAX_ITEMS) die("too many --tail");
            opt.tails[opt.ntails++] = parse_tail(argv[++i]);
        } else if (!strcmp(a, "--map")) {
            need(i, argc, 3, a);
            if (opt.nseeds == MAX_ITEMS) die("too many --map");
            opt.seeds[opt.nseeds].map = argv[i + 1];
            opt.seeds[opt.nseeds].key = unhex(argv[i + 2]);
            opt.seeds[opt.nseeds].val = unhex(argv[i + 3]);
            opt.nseeds++;
            i += 3;
        } else if (!strcmp(a, "--pkt")) {
            need(i, argc, 1, a); opt.pkt = unhex(argv[++i]);
        } else if (!strcmp(a, "--ctx")) {
            need(i, argc, 2, a);
            opt.have_ctx = 1;
            opt.ifindex = (unsigned)strtoul(argv[i + 1], NULL, 0);
            opt.rxq = (unsigned)strtoul(argv[i + 2], NULL, 0);
            i += 2;
        } else if (!strcmp(a, "--dump")) {
            need(i, argc, 2, a);
            if (opt.ndumps == MAX_ITEMS) die("too many --dump");
            opt.dumps[opt.ndumps].map = argv[i + 1];
            opt.dumps[opt.ndumps].key = unhex(argv[i + 2]);
            opt.ndumps++;
            i += 2;
        } else if (!strcmp(a, "--dump-all")) {
            need(i, argc, 1, a);
            if (opt.ndumps == MAX_ITEMS) die("too many --dump-all");
            opt.dumps[opt.ndumps].map = argv[++i];
            opt.dumps[opt.ndumps].all = 1;
            opt.ndumps++;
        } else if (!strcmp(a, "--dump-bss")) {
            opt.dump_bss = 1;
        } else if (!strcmp(a, "--data-out")) {
            opt.data_out = 1;
        } else {
            die("unknown argument %s", a);
        }
    }
    if (!opt.obj || !opt.prog)
        die("--obj and --prog are required");
    if (opt.pkt.n < 14)
        die("--pkt must be at least 14 bytes (ETH_HLEN), got %zu", opt.pkt.n);
    if (opt.pkt.n > PKT_MAX)
        die("--pkt is longer than %d bytes", PKT_MAX);

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(opt.cpu, &set);
    if (sched_setaffinity(0, sizeof set, &set))
        die("cannot pin to cpu %d: %s", opt.cpu, strerror(errno));

    struct utsname u;
    uname(&u);
    printf("version libbpf %u.%u kernel %s\n", libbpf_major_version(),
           libbpf_minor_version(), u.release);
    for (int n = 0; n < opt.cycles; n++)
        cycle(n);
    return 0;
}
