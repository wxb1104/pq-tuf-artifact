#!/usr/bin/env bash
set -e
pip install -q numpy pandas matplotlib
python - <<'PY'
import numpy, pandas, matplotlib
print("analy deps ok", numpy.__version__, pandas.__version__, matplotlib.__version__)
PY
