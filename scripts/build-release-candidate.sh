#!/usr/bin/env bash
# Build reviewable artifacts only. Signing is a separate trusted CI job.
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/release_security.py check --output build/security --require-clean
[[ "${GITHUB_RUN_NUMBER:-}" =~ ^[1-9][0-9]*$ ]] || { echo 'trusted release sequence is required' >&2; exit 1; }
[[ "${GITHUB_REPOSITORY:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'trusted repository is required' >&2; exit 1; }
[[ ! -e build/candidate ]] || { echo 'candidate directory already exists' >&2; exit 1; }
[[ -s web/admin-ui/dist/index.html ]] || { echo 'build the admin UI first' >&2; exit 1; }
mkdir -p build/candidate
python3 - <<'PY'
import json
from pathlib import Path
boms = [json.loads(Path('build/security/' + name + '-sbom.json').read_text()) for name in ('go', 'npm')]
components = [item for bom in boms for item in [bom['metadata']['component'], *bom['components']]]
refs = [item['bom-ref'] for item in components if 'bom-ref' in item]
if len(refs) != len(set(refs)):
    raise SystemExit('duplicate component references in combined SBOM')
bom = {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
       'metadata': {'component': {'type': 'application', 'name': 'AegisNAS Pi4'}},
       'components': components,
       'dependencies': [item for source in boms for item in source.get('dependencies', [])]}
Path('build/candidate/sbom.cdx.json').write_text(json.dumps(bom, indent=2) + '\n')
PY
for arch in amd64 arm64; do
  stage="build/candidate/stage-$arch"
  mkdir -p "$stage/bin" "$stage/web/admin-ui" "$stage/security"
  for cmd in cmd/*; do
    [[ -f "$cmd/main.go" ]] || continue
    CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -p=2 -trimpath -o "$stage/bin/$(basename "$cmd")" "./$cmd"
  done
  cp -R web/admin-ui/dist "$stage/web/admin-ui/"
  cp -R build/security/. "$stage/security/"
  cp build/candidate/sbom.cdx.json "$stage/security/"
  cp LICENSE README.md "$stage/"
  git rev-parse HEAD > "$stage/SOURCE_COMMIT"
  python3 - "$stage" "$arch" <<'PY'
import json, os, sys
from pathlib import Path
stage = Path(sys.argv[1])
manifest = {'schema_version': 1, 'source_commit': (stage / 'SOURCE_COMMIT').read_text().strip(),
            'repository': os.environ['GITHUB_REPOSITORY'], 'platform': 'linux-' + sys.argv[2],
            'release_sequence': int(os.environ['GITHUB_RUN_NUMBER'])}
(stage / 'release.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
  (cd "$stage" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
  tar -C "$stage" -czf "build/candidate/aegisnas-linux-$arch.tar.gz" .
done
# Reject source/lockfile changes during the build, too.
python3 scripts/release_security.py check --output build/security --require-clean
(cd build/candidate && sha256sum aegisnas-linux-*.tar.gz sbom.cdx.json > SHA256SUMS)
