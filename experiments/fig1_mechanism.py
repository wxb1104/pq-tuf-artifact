#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fig.1 system/mechanism overview for PQ-TUF/Uptane (v2, no overlaps)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Circle
from matplotlib.lines import Line2D

C_C   = "#9aa3ad"; C_H = "#0072b2"; C_Q = "#009e73"
C_BOX = "#eef3f8"; C_SIGN = "#dceaf6"; C_VER = "#e7f4ec"
C_DIR = "#fdf0e0"; C_IMG = "#efe9f6"; C_VEH = "#e9f1f3"
C_RED = "#cc0000"; C_TXT = "#1a1a1a"

fig, ax = plt.subplots(figsize=(13.4, 9.6))
ax.set_xlim(0, 140); ax.set_ylim(0, 100); ax.axis("off")

def box(x, y, w, h, fc, ec="#33424e", lw=1.3, r=0.025, z=2, ls="-"):
    p = FancyBboxPatch((x, y), w, h,
        boxstyle=f"round,pad=0.0,rounding_size={r*100}",
        fc=fc, ec=ec, lw=lw, zorder=z, linestyle=ls)
    ax.add_patch(p); return p

def txt(x, y, s, size=9, w="normal", ha="center", va="center",
        color=C_TXT, z=5, style="normal"):
    ax.text(x, y, s, fontsize=size, fontweight=w, ha=ha, va=va,
            color=color, zorder=z, fontstyle=style)

def arrow(x1, y1, x2, y2, color="#33424e", lw=1.6, ms=14, z=3, ls="-"):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>",
        mutation_scale=ms, lw=lw, color=color, zorder=z, linestyle=ls,
        shrinkA=2, shrinkB=2))

def keytokens(x, y, classes, scale=1.0):
    d = 3.1*scale
    x0 = x - (len(classes)*d)/2 + d/2
    for i, cl in enumerate(classes):
        col = {"C": C_C, "H": C_H, "Q": C_Q}[cl]
        ax.add_patch(Circle((x0+i*d, y), 1.1*scale, fc=col, ec="#222", lw=0.7, zorder=6))
        txt(x0+i*d, y, cl, size=6.2*scale, w="bold", color="white")

for yy, lab in [(95, "SIGN"), (72.5, "QUORUM"), (54, "VERIFY"),
                (34.5, "DISTRIBUTE"), (13, "VEHICLE")]:
    txt(2.2, yy, lab, size=8, w="bold", color="#7a8794", style="italic")
ax.add_line(Line2D([5.2, 5.2], [4, 99], color="#d7dde2", lw=1.0, zorder=1))

# ---- Layer 0: roles ----
txt(72, 99.0, "Repository roles  (independent accountable signers, TUF roles + TAP-3)",
    size=10.5, w="bold")
roles = [
    ("root", "offline anchor", "ML-DSA-87 / H", "HHHHC", 3, 2),
    ("timestamp", "online, every update", "ML-DSA-44 / H", "HHC", 2, 1),
    ("snapshot", "online, every update", "ML-DSA-44/65 / H", "HHC", 2, 1),
    ("targets", "semi-online", "ML-DSA-65 / H", "HHCC", 3, 1),
    ("delegated (TAP-3)", "per supplier", "Q / H roles", "HHC", 2, 1),
]
rw, rh, gap, x0, ytop = 24.5, 13.0, 1.8, 7.0, 83.0
centers = []
for i, (name, sub, sch, cls, t, k) in enumerate(roles):
    x = x0 + i*(rw+gap); cx = x+rw/2; centers.append(cx)
    box(x, ytop, rw, rh, C_BOX, ec="#3a5a78", lw=1.4)
    txt(cx-3.2, ytop+rh-1.9, name, size=9.0, w="bold")
    txt(cx+rw/2-2.2, ytop+rh-1.9, f"($t$={t}, $k$={k})", size=7.6,
        ha="right", color="#0b4f7a", w="bold")
    keytokens(cx, ytop+rh-5.0, cls)
    txt(cx, ytop+3.0, sub, size=6.8, color="#555")
    txt(cx, ytop+1.2, sch, size=7.0, color="#0b4f7a", style="italic")

# ---- Layer 1: QSign ----
ys = 64.5
box(7, ys, 126, 12.0, C_SIGN, ec="#2f6f9b", lw=1.5)
txt(25, ys+8.8, "QSign  (Alg. 1)", size=9.4, w="bold")
txt(25, ys+4.6, "quorum-aware scheduling:\n$q_{min}=\\max\\{k,\\,t-c\\}$ quantum-safe,\n$(t-q_{min})$ classical signers",
    size=7.4)
txt(66, ys+9.2, "hybrid signature  $\\sigma_H=\\ell(\\sigma_C)\\,\\|\\,\\sigma_C\\,\\|\\,\\sigma_Q$", size=8.4)
txt(66, ys+6.0, "domain separator  $\\tau_C,\\tau_Q$  (scheme + component binding)", size=7.8)
txt(66, ys+2.8, "length prefix $\\ell$: unambiguous split, anti-stripping / anti-downgrade", size=7.8)
txt(111, ys+7.4, "canonical JSON  $c_r=\\mathsf{CJ}(P_r)$;\none keyid $\\to$ one slot", size=7.8)
txt(111, ys+3.0, "no aggregation, no MPC", size=7.6, color="#7a3b00", w="bold")
for cx in centers:
    arrow(cx, ytop, cx, ys+12.0, color="#3a5a78", lw=1.1, ms=10)

# ---- Layer 2: metadata + QVerify + attacker ----
yv = 45.0
box(7, yv, 33, 13.5, "#ffffff", ec="#33424e", lw=1.3)
txt(23.5, yv+11.3, "Signed metadata  $M_r=(P_r,\\mathcal{S}_r)$", size=8.6, w="bold")
for j, fn in enumerate(["root.json", "timestamp.json", "snapshot.json", "targets.json"]):
    yy = yv+8.7-j*2.4
    box(9.5, yy-0.9, 28, 1.9, "#f4f6f8", ec="#aeb8c0", lw=0.7, r=0.012)
    txt(23.5, yy, fn + "   { signatures:[...], signed:{...} }", size=6.7)
box(44, yv, 62, 13.5, C_VER, ec="#1e7a4d", lw=1.5)
txt(75, yv+11.5, "QVerify  (Alg. 2)", size=9.4, w="bold")
txt(75, yv+8.7, "1. algorithm whitelist  (reject unregistered / legacy key type)", size=7.8)
txt(75, yv+6.4, "2. per-keyid verify, set-union  $\\Rightarrow$  one keyid, one vote", size=7.8)
txt(75, yv+4.1, "3. count valid votes $|V|$ and quantum-safe votes $Q$", size=7.8)
txt(75, yv+1.6, "accept  iff  $|V|\\geq t$  AND  $Q\\geq k$", size=9.0, w="bold", color="#126a41")
arrow(40, yv+6.7, 44, yv+6.7)
box(110, yv+1.5, 23, 10.5, "#fdecec", ec=C_RED, lw=1.4, ls=(0,(4,2)))
txt(121.5, yv+9.7, "CRQC adversary", size=8.6, w="bold", color=C_RED)
txt(121.5, yv+6.9, "forges classical $\\sigma_C$;\nassembles all-classical quorum", size=7.0, color=C_RED)
txt(121.5, yv+2.7, "blocked: $Q<k$ rejected (G2/G3)", size=7.4, w="bold", color=C_RED)
arrow(110, yv+6.7, 106, yv+6.7, color=C_RED, lw=1.6, ms=13)
arrow(40, ys, 23.5, yv+13.5, color="#2f6f9b", lw=1.4)

# ---- Layer 3: repositories ----
yr = 25.5
box(7, yr, 61, 14.0, C_DIR, ec="#c8772b", lw=1.5)
txt(37.5, yr+12.2, "Director repository  (online, vehicle-aware, no delegation)",
    size=9.0, w="bold", color="#9a5512")
txt(37.5, yr+9.4, "timestamp $\\cdot$ snapshot $\\cdot$ targets  (signs on demand)", size=7.8)
box(10, yr+2.0, 55, 4.8, "#fff7ee", ec="#d99a5b", lw=1.0)
txt(37.5, yr+4.4, "BOOT dual-threshold root rotation (Alg. 3):\n"
    "$\\geq t_{old}$ old-side  AND  $\\geq t_{new}$ new-side, $Q\\geq k_{new}$, version $+1$",
    size=7.4, color="#9a5512")
box(72, yr, 61, 14.0, C_IMG, ec="#6b4a96", lw=1.5)
txt(102.5, yr+12.2, "Image repository  (human-operated, may delegate)",
    size=9.0, w="bold", color="#4d3273")
txt(102.5, yr+9.4, "timestamp $\\cdot$ snapshot $\\cdot$ targets + TAP-3 delegations", size=7.8)
box(75, yr+2.0, 55, 4.8, "#f6f1fb", ec="#9a82bd", lw=1.0)
txt(102.5, yr+4.4, "full chain retained for replay;\nold keys deprecated only after all clients advance",
    size=7.4, color="#4d3273")
arrow(60, yv, 37.5, yr+14.0, color="#1e7a4d", lw=1.4)
arrow(90, yv, 102.5, yr+14.0, color="#1e7a4d", lw=1.4)

# ---- Layer 4: vehicle ----
yv2 = 5.0
box(7, yv2, 68, 15.0, C_VEH, ec="#2f6f7a", lw=1.5)
txt(41, yv2+13.0, "Primary ECU  -  full verification  $\\mathcal{R}^{full}$",
    size=9.2, w="bold", color="#1f5560")
txt(41, yv2+10.2, "walks root$\\to$timestamp$\\to$snapshot$\\to$targets on BOTH chains;\n"
    "Director/Image targets agree on length & hashes", size=7.6)
box(10, yv2+1.6, 62, 4.2, "#f3f8f9", ec="#6fa6b0", lw=1.0)
txt(41, yv2+3.7, "verify cost  $T_{FULL}=t\\,v_C + k\\,v_Q$   (linear in $k$)", size=8.0)
sx0, sw, sg = 79.0, 17.7, 1.9
for i in range(3):
    x = sx0+i*(sw+sg)
    box(x, yv2, sw, 15.0, "#eef6ee", ec="#3b8c5f", lw=1.3)
    txt(x+sw/2, yv2+12.4, f"Secondary\nECU {i+1}", size=8.2, w="bold", color="#206c43")
    txt(x+sw/2, yv2+8.0, "partial verify\n$\\mathcal{R}^{part}=$\n{ts$^D$, tgt$^D$}",
        size=6.9, color="#206c43")
    txt(x+sw/2, yv2+2.6, "flash/RAM\nbudget $W$", size=6.9, color="#206c43")
arrow(37.5, yr, 37.5, yv2+15.0, color="#2f6f7a", lw=1.6)
arrow(102.5, yr, 58, yv2+15.0, color="#2f6f7a", lw=1.4)
arrow(75, yv2+9.0, 79, yv2+9.0, color="#3b8c5f", lw=1.8, ms=16)

# ---- legend ----
leg = [("C classical key", C_C), ("H hybrid (C$\\|$Q)", C_H), ("Q pure post-quantum", C_Q)]
lx = 8.0
for name, col in leg:
    ax.add_patch(Circle((lx, 1.7), 0.95, fc=col, ec="#222", lw=0.7, zorder=6))
    txt(lx+2.0, 1.7, name, size=7.2, ha="left")
    lx += 30
txt(132, 1.7, "$t$=threshold, $k$=required quantum-safe signers", size=7.2, ha="right",
    color="#33424e", style="italic")

plt.subplots_adjust(left=0.01, right=0.99, top=0.99, bottom=0.01)
out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results", "figures", "fig_mechanism")
fig.savefig(out + ".pdf", bbox_inches="tight")
fig.savefig(out + ".png", dpi=200, bbox_inches="tight")
print("saved", out)
