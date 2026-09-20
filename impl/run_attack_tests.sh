#!/usr/bin/env bash
set -e
if [ -z "${VIRTUAL_ENV:-}" ] && [ -f "$HOME/tufspike/bin/activate" ]; then
  source "$HOME/tufspike/bin/activate"
fi
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python tests/test_client_attacks.py
echo "=== ATTACK TESTS DONE ==="
