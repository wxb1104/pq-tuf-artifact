#!/usr/bin/env python3
"""E7 -- verify-only MCU footprint (flash/RAM) and verification peak heap of
PQClean signature verifiers, portable clean-C vs AVX2-optimized.

Method (mirrors the code-size methodology of PQ migration studies):
  * compile one scheme's PQClean implementation (+ PQClean common) with
    -ffunction-sections -fdata-sections -O3;
  * link a harness whose only PQ entry point is crypto_sign_open (verify),
    with --gc-sections so keygen/sign-unreachable code is dropped;
  * the ELF is dynamically linked (libc not counted); subtract, section by
    section, an identically built scaffolding baseline (crt + malloc wrapper,
    no PQ code). The difference is the verify-reachable PQ+common footprint,
    independent of PQCLEAN symbol-prefix conventions;
  * peak live heap during crypto_sign_open is measured by header-instrumented
    malloc/calloc/realloc/free wrappers;
  * max single-function stack frame comes from -fstack-usage (conservative:
    not summed along the call chain).

This is a clean-C/AVX2 x86 proxy, NOT a cross-compiled ARM/RPi measurement:
there is no QEMU/ARM toolchain on this host, so absolute MCU numbers are an
evidence-backed proxy (stated explicitly in the paper).
"""
import os, csv, subprocess, glob, sys, re

_reg_root = os.path.join(os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo")),
                         "registry", "src")
_hits = glob.glob(os.path.join(_reg_root, "*", "pqcrypto-dilithium-*", "pqclean"))
PQ = sorted(_hits)[-1] if _hits else ""
if not PQ:
    sys.exit("PQClean sources not found; run (cd impl/pqbench && cargo fetch) first.")
COMMON = os.path.join(PQ, "common")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E7 = os.path.join(ROOT, "impl", "e7_footprint")
OUT = os.path.join(ROOT, "results", "e7_budget")
os.makedirs(OUT, exist_ok=True)

SCHEMES = [
    ("mldsa44", "dilithium2"),
    ("mldsa65", "dilithium3"),
    ("mldsa87", "dilithium5"),
    ("fndsa512", "falcon-512"),
    ("fndsa1024", "falcon-1024"),
    ("slhdsa128s", "sphincs-sha2-128s-simple"),
    ("slhdsa128f", "sphincs-sha2-128f-simple"),
    ("slhdsa256s", "sphincs-sha2-256s-simple"),
    ("slhdsa256f", "sphincs-sha2-256f-simple"),
]
COMMON_SRCS = ["fips202.c", "sha2.c", "aes.c", "sp800-185.c",
               "nistseedexpander.c", "randombytes.c"]

BASE_C = r'''
#include <stdlib.h>
#include <stdio.h>
#define HDR 32
static size_t g_cur=0,g_peak=0;
static size_t al(size_t n){return (n+15u)&~(size_t)15u;}
void *__wrap_malloc(size_t n){unsigned char*r=__real_malloc(n+HDR);if(!r)return 0;
 size_t a=al(n);memcpy?0:0;g_cur+=a;if(g_cur>g_peak)g_peak=g_cur;return r+HDR;}
void __wrap_free(void*p){if(!p)return;unsigned char*r=(unsigned char*)p-HDR;
 size_t a;memcpy(&a,r,sizeof(a));g_cur-=a;__real_free(r);}
int main(void){void*p=malloc(1024);free(p);printf("BASE peak=%zu\n",g_peak);return 0;}
'''
# NOTE: baseline uses its own correct wrapper file below (string kept simple)
BASE_C = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define HDR 32
static size_t g_cur=0,g_peak=0;
static size_t al16(size_t n){return (n+15u)&~(size_t)15u;}
void *__wrap_malloc(size_t n){unsigned char*r=__real_malloc(n+HDR);if(!r)return 0;
 size_t a=al16(n);memcpy(r,&a,sizeof(a));g_cur+=a;if(g_cur>g_peak)g_peak=g_cur;return r+HDR;}
void *__wrap_calloc(size_t x,size_t y){size_t n=x*y;unsigned char*r=__real_malloc(n+HDR);
 if(!r)return 0;memset(r+HDR,0,n);size_t a=al16(n);memcpy(r,&a,sizeof(a));
 g_cur+=a;if(g_cur>g_peak)g_peak=g_cur;return r+HDR;}
void __wrap_free(void*p){if(!p)return;unsigned char*r=(unsigned char*)p-HDR;
 size_t a;memcpy(&a,r,sizeof(a));g_cur-=a;__real_free(r);}
void *__wrap_realloc(void*p,size_t n){if(!p)return __wrap_malloc(n);
 unsigned char*o=(unsigned char*)p-HDR;size_t oa;memcpy(&oa,o,sizeof(oa));
 unsigned char*r=__real_realloc(o,n+HDR);if(!r)return 0;size_t na=al16(n);
 memcpy(r,&na,sizeof(na));g_cur+=(na>oa)?na-oa:0;if(g_cur>g_peak)g_peak=g_cur;return r+HDR;}
int main(void){void*p=malloc(1024);void*q=realloc(p,2048);free(q);
 printf("BASE peak=%zu\n",g_peak);return 0;}
'''


def run(cmd, cwd=None):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(cmd)}\n{r.stderr}\n{r.stdout}")
    return r.stdout


def section_sizes(elf):
    """Parse `size -A -d`: return dict section->bytes, classified."""
    out = run(["size", "-A", "-d", elf])
    sec = {}
    for line in out.splitlines()[1:]:
        p = line.split()
        if len(p) >= 2 and p[0].startswith("."):
            try:
                sec[p[0]] = int(p[1])
            except ValueError:
                pass
    cls = {"code": 0, "rodata": 0, "data": 0, "bss": 0}
    for name, v in sec.items():
        if name.startswith(".bss"):
            cls["bss"] += v
        elif name.startswith(".rodata") or name.startswith(".data.rel.ro"):
            cls["rodata"] += v
        elif name.startswith(".data"):
            cls["data"] += v
        elif name.startswith(".text") or name.startswith(".init") \
                or name.startswith(".fini"):
            cls["code"] += v
    return cls


def compile_objs(srcs, outdir, flags, includes, asm=None):
    os.makedirs(outdir, exist_ok=True)
    objs = []
    for s in srcs:
        o = os.path.join(outdir, os.path.basename(s).replace(".c", ".o"))
        run(["gcc", *flags.split(), *includes, "-c", s, "-o", o])
        objs.append(o)
    for s in asm or []:
        o = os.path.join(outdir, os.path.basename(s).replace(".S", ".o"))
        run(["gcc", "-O3", "-march=native", *includes, "-c", s, "-o", o])
        objs.append(o)
    return objs


def link(objs, harness, out, flags, includes=None):
    ho = out.replace(".out", "_harness.o")
    run(["gcc", *flags.split(), *(includes or []), "-c", harness, "-o", ho])
    run(["gcc", *flags.split(), "-o", out, *objs, ho, "-Wl,--gc-sections",
         "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
         "-Wl,--wrap=realloc"])
    return out


def max_stack_frame(outdir):
    m = 0
    for su in glob.glob(os.path.join(outdir, "*.su")):
        if os.path.basename(su).startswith("harness") or \
           os.path.basename(su).startswith("baseline"):
            continue
        with open(su) as f:
            for line in f:
                parts = line.rsplit("\t", 2)
                if len(parts) >= 2:
                    try:
                        m = max(m, int(parts[1]))
                    except ValueError:
                        pass
    return m


def build_baseline(work, tier, flags):
    bdir = os.path.join(work, f"baseline_{tier}")
    os.makedirs(bdir, exist_ok=True)
    bc = os.path.join(bdir, "baseline.c")
    with open(bc, "w") as f:
        f.write(BASE_C)
    out = os.path.join(bdir, "base.out")
    bo = os.path.join(bdir, "baseline.o")
    run(["gcc", *flags.split(), "-c", bc, "-o", bo])
    run(["gcc", *flags.split(), "-o", out, bo, "-Wl,--gc-sections",
         "-Wl,--wrap=malloc", "-Wl,--wrap=calloc", "-Wl,--wrap=free",
         "-Wl,--wrap=realloc"])
    return section_sizes(out)


def make_shim(sdir, w):
    """The vendored PQClean api.h exposes only PQCLEAN_<NS>_ names. Generate a
    shim that aliases them to the generic NIST names used by the harness."""
    txt = open(os.path.join(sdir, "api.h")).read()
    m = re.search(r"(PQCLEAN_[A-Za-z0-9_]+)_CRYPTO_PUBLICKEYBYTES", txt)
    ns = m.group(1)
    shim = (
        '#include "api.h"\n'
        f'#define CRYPTO_PUBLICKEYBYTES {ns}_CRYPTO_PUBLICKEYBYTES\n'
        f'#define CRYPTO_SECRETKEYBYTES {ns}_CRYPTO_SECRETKEYBYTES\n'
        f'#define CRYPTO_BYTES {ns}_CRYPTO_BYTES\n'
        f'#define crypto_sign_keypair {ns}_crypto_sign_keypair\n'
        f'#define crypto_sign {ns}_crypto_sign\n'
        f'#define crypto_sign_open {ns}_crypto_sign_open\n'
    )
    with open(os.path.join(w, "pqtuf_api.h"), "w") as f:
        f.write(shim)


def main():
    only = sys.argv[1:]
    rows = []
    work = os.path.join(E7, "build")
    harness = os.path.join(E7, "harness.c")
    common_full = [os.path.join(COMMON, c) for c in COMMON_SRCS
                   if os.path.exists(os.path.join(COMMON, c))]
    base = {}
    for tier, flags in (
            ("portable", "-O3 -ffunction-sections -fdata-sections "
                         "-march=x86-64 -mno-avx2 -fstack-usage"),
            ("avx2", "-O3 -ffunction-sections -fdata-sections "
                     "-march=native -fstack-usage")):
        base[tier] = build_baseline(work, tier, flags)

    for key, dirname in SCHEMES:
        if only and key not in only:
            continue
        tiers = [("portable", "clean")]
        if os.path.isdir(os.path.join(PQ, "crypto_sign", dirname, "avx2")):
            tiers.append(("avx2", "avx2"))
        for tier, impl in tiers:
            flags = ("-O3 -ffunction-sections -fdata-sections -march=x86-64 "
                     "-mno-avx2 -fstack-usage") if tier == "portable" else \
                    ("-O3 -ffunction-sections -fdata-sections -march=native "
                     "-fstack-usage")
            sdir = os.path.join(PQ, "crypto_sign", dirname, impl)
            w = os.path.join(work, tier, key)
            os.makedirs(w, exist_ok=True)
            for old in glob.glob(os.path.join(w, "*")):
                os.remove(old)
            csrcs = sorted(glob.glob(os.path.join(sdir, "*.c")))
            asms = sorted(glob.glob(os.path.join(sdir, "*.S")))
            # common objects built per-scheme dir so -fstack-usage lands in w
            common_objs = compile_objs(
                common_full, w, flags,
                ["-I" + sdir, "-I" + COMMON])
            scheme_objs = compile_objs(
                csrcs, w, flags, ["-I" + sdir, "-I" + COMMON], asm=asms)
            make_shim(sdir, w)
            out = os.path.join(w, "a.out")
            link(common_objs + scheme_objs, harness, out, flags,
                 includes=["-I" + w, "-I" + sdir, "-I" + COMMON])
            res = run([out]).strip()
            heap = int(res.split("HEAP_PEAK=")[1]) if "HEAP_PEAK=" in res \
                else -1
            if not res.startswith("VERIFY_RC=0"):
                print(f"  !! {key}/{tier} verify failed: {res}")
            full = section_sizes(out)
            b = base[tier]
            code = full["code"] - b["code"]
            rod = full["rodata"] - b["rodata"]
            dat = max(0, full["data"] - b["data"])
            bss = max(0, full["bss"] - b["bss"])
            stk = max_stack_frame(w)
            rows.append({
                "scheme": key, "tier": tier, "impl": impl,
                "flash_code_B": code, "rodata_B": rod, "data_B": dat,
                "bss_B": bss, "flash_total_B": code + rod + dat,
                "static_ram_B": dat + bss, "heap_peak_verify_B": heap,
                "max_stack_frame_B": stk,
            })
            print(f"  {key:10s} {tier:8s} flash={code+rod+dat:7d} "
                  f"(code={code} rod={rod} data={dat}) bss={bss} "
                  f"heap={heap} stk={stk}")

    cols = ["scheme", "tier", "impl", "flash_code_B", "rodata_B", "data_B",
            "bss_B", "flash_total_B", "static_ram_B", "heap_peak_verify_B",
            "max_stack_frame_B"]
    with open(os.path.join(OUT, "e7_footprint.csv"), "w", newline="") as f:
        wcsv = csv.DictWriter(f, fieldnames=cols)
        wcsv.writeheader()
        wcsv.writerows(rows)
    print("wrote", os.path.join(OUT, "e7_footprint.csv"))


if __name__ == "__main__":
    main()
