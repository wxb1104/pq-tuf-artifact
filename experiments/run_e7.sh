#!/usr/bin/env bash
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 experiments/e7_footprint.py "$@"
