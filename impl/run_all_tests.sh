#!/usr/bin/env bash
# Full unit/integration/attack regression for the pqtuf package.
if [ -z "${VIRTUAL_ENV:-}" ] && [ -f "$HOME/tufspike/bin/activate" ]; then
  source "$HOME/tufspike/bin/activate"
fi
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
rc=0
for t in tests/smoke_keys.py tests/test_quorum_logic.py tests/test_repo_integration.py tests/test_client_attacks.py; do
  echo "================ $t ================"
  python "$t" || rc=1
done
echo "ALL_REGRESSION_RC=$rc"
exit $rc
