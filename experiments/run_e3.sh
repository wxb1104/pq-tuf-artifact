#!/usr/bin/env bash
if [ -z "${VIRTUAL_ENV:-}" ] && [ -f "$HOME/tufspike/bin/activate" ]; then
  source "$HOME/tufspike/bin/activate"
fi
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python experiments/e3_attack_matrix.py
