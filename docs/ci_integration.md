# CI/CD Integration Guide — Supply Chain Defender

## GitHub Actions Workflow

See `.github/workflows/supply-chain-guard.yml` for the ready-to-use workflow.

## CI Defense Layers

### Layer 1: Lockfile Diff Gate

Block PRs that introduce suspicious dependency changes:

```yaml
- name: Check lockfile changes
  run: |
    if git diff --name-only origin/main...HEAD | grep -E "package-lock\.json|yarn\.lock|pnpm-lock\.yaml"; then
      echo "::warning::Lockfile changed — running supply chain scan"
      python -m scd ci-guard . --strict --format json --output scd-report.json
    fi
```

### Layer 2: Unexpected Transitive Dependency Alerts

Monitor for new packages appearing in the dependency tree:

```bash
# Compare lockfile deps before and after
git show origin/main:package-lock.json | python -c "
import json, sys
data = json.load(sys.stdin)
pkgs = set()
for key in data.get('packages', {}):
    if key:
        name = key.split('node_modules/')[-1]
        pkgs.add(name)
for p in sorted(pkgs):
    print(p)
" > /tmp/deps-before.txt

python -c "
import json
with open('package-lock.json') as f:
    data = json.load(f)
pkgs = set()
for key in data.get('packages', {}):
    if key:
        name = key.split('node_modules/')[-1]
        pkgs.add(name)
for p in sorted(pkgs):
    print(p)
" > /tmp/deps-after.txt

# Show new dependencies
comm -13 /tmp/deps-before.txt /tmp/deps-after.txt > /tmp/new-deps.txt
if [ -s /tmp/new-deps.txt ]; then
    echo "::warning::New dependencies introduced:"
    cat /tmp/new-deps.txt
fi
```

### Layer 3: Install-Time Protections

```bash
# Use npm ci (not npm install) in CI
npm ci --ignore-scripts  # Install without running any scripts

# If scripts are needed, audit them first
npm ci --ignore-scripts
python -m scd ci-guard . --strict
npm rebuild  # Now run scripts after scan passes
```

### Layer 4: Exact Version Pinning Strategy

In `package.json`:
```json
{
  "dependencies": {
    "axios": "1.13.0"
  }
}
```

Do NOT use:
- `^1.13.0` (allows 1.14.1)
- `~1.13.0` (allows 1.13.x)
- `*` or `latest` (allows anything)
- `>=1.0.0` (allows anything)

Enforce with ESLint or CI check:
```bash
# Check for non-exact versions in package.json
python -c "
import json, sys
with open('package.json') as f:
    data = json.load(f)
problems = []
for section in ['dependencies', 'devDependencies']:
    for name, ver in data.get(section, {}).items():
        if ver.startswith('^') or ver.startswith('~') or ver in ('*', 'latest'):
            problems.append(f'{section}.{name}: {ver}')
if problems:
    print('Non-exact versions found:')
    for p in problems:
        print(f'  {p}')
    sys.exit(1)
"
```

### Layer 5: Known-Bad Package Denylist

The `scd ci-guard` command enforces the policy denylist automatically. Custom entries:

```json
{
  "blocked_packages": [
    {"name": "your-internal-banned-package", "reason": "Deprecated — use new-package instead"}
  ]
}
```

### Layer 6: Script Execution Policy

In project `.npmrc`:
```ini
ignore-scripts=true
```

Then whitelist known-safe scripts:
```json
{
  "scripts": {
    "postinstall": "echo 'Postinstall scripts disabled for security. Use npm rebuild for native modules.'"
  }
}
```

### Layer 7: Provenance and Release Anomaly Detection

```bash
# Check npm provenance (if available)
npm audit signatures 2>/dev/null

# Check package publish date for anomalies
npm view axios time --json | python -c "
import json, sys
times = json.load(sys.stdin)
for ver, ts in sorted(times.items()):
    if ver in ('1.14.1', '0.30.4'):
        print(f'SUSPICIOUS: {ver} published at {ts}')
"
```

### Layer 8: Build Failure Rules

```yaml
# In CI: fail build on any HIGH+ finding
- name: Supply Chain Guard
  run: python -m scd ci-guard . --fail-on HIGH
  # Exit code 2 = compromised → build fails
  # Exit code 1 = warnings → build passes (override with --strict)
  # Exit code 0 = clean
```

### Layer 9: Secrets Protection During Builds

```yaml
# Minimize secret exposure: only inject when needed
jobs:
  install:
    runs-on: ubuntu-latest
    # NO secrets in this job — just install and scan
    steps:
      - uses: actions/checkout@v4
      - run: npm ci --ignore-scripts
      - run: pip install supply-chain-defender && python -m scd ci-guard . --strict

  deploy:
    needs: install  # Only runs after scan passes
    runs-on: ubuntu-latest
    environment: production  # Secrets only here
    steps:
      - run: npm run deploy
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
```
