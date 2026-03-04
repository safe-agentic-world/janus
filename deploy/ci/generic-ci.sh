#!/usr/bin/env sh
set -eu

go build -o ./bin/nomos ./cmd/nomos

./bin/nomos doctor -c ./examples/quickstart/config.quickstart.json --format json

./bin/nomos policy test --action ./examples/quickstart/actions/allow-readme.json --bundle ./policies/safe-dev-hardened.yaml
./bin/nomos policy test --action ./examples/quickstart/actions/deny-env.json --bundle ./policies/safe-dev-hardened.yaml

cp ./examples/quickstart/config.quickstart.json ./examples/quickstart/config.invalid.json
python - <<'PY'
import json
path = "./examples/quickstart/config.invalid.json"
with open(path, "r", encoding="utf-8") as handle:
    data = json.load(handle)
data["policy"]["policy_bundle_path"] = "./missing.yaml"
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle)
PY

if ./bin/nomos doctor -c ./examples/quickstart/config.invalid.json --format json; then
  echo "expected invalid config to fail closed"
  exit 1
fi
