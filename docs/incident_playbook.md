# Incident Response Playbook — npm Supply Chain Attack (Axios Compromise)

> **Advisory:** GHSA-fw8c-xr5c-95f9 | MAL-2026-2306 | SNYK-JS-AXIOS-15850650
> **Attack window:** 2026-03-31 00:21 UTC – 03:29 UTC (3h 8m)
> **Status:** Both malicious packages removed from npm registry. Security placeholders published.
> **Safe versions:** axios ≤ 1.14.0 or ≥ 1.14.2; axios ≤ 0.30.3 in the 0.x series

## PHASE 1 — BRUTAL DIAGNOSIS

### What The Real Risk Is

This is not a theoretical risk. The attack works like this:

1. Attacker hijacked the npm account of axios maintainer `jasonsaayman` on 2026-03-31 at 00:21 UTC
2. Published `axios@1.14.1` and `axios@0.30.4` — both declare `plain-crypto-js@4.2.1` as a dependency (typosquat of `crypto-js`)
3. `plain-crypto-js@4.2.1` runs a postinstall script that:
   - Reads ALL environment variables from the process
   - Filters for high-value secrets (AWS keys, GitHub tokens, npm tokens, DB URLs, API keys)
   - Encodes and **exfiltrates them via HTTPS to `sfrclak.com:8000` (IP: `142.11.206.73`)**
   - Executes a self-destruct routine to remove postinstall artifacts and hinder forensics
4. Any `npm install` that resolved to these versions **executed the malicious code**
5. Exfiltration is instant — by the time you notice, credentials are already stolen
6. npm removed both packages at 03:29 UTC; security placeholders (`0.0.1-security.0`) now occupy those names

### Unsafe Assumptions

| Assumption | Reality |
|---|---|
| "I only have it in my lockfile" | If `npm install` ran, the code executed. Lockfile presence + install = compromise |
| "I removed the bad version" | Removal cleans future installs. **Past exfiltration already happened.** Credentials are gone. |
| "My CI passed" | CI is the HIGHEST value target. CI secrets (deploy keys, npm tokens, cloud creds) are the prize |
| "I use `npm ci`" | `npm ci` respects the lockfile. If the lockfile has the bad version, `npm ci` installs it faithfully |
| "I don't use axios directly" | Transitive dependencies. If ANY dep in your tree pulls axios, you're exposed |
| "I checked and my version is fine" | Check the LOCKFILE, not package.json. Ranges like `^1.14.0` resolve to `1.14.1` |
| "It's a dev dependency so it's fine" | `npm install` installs devDeps by default. Postinstall scripts run regardless of dep type |
| "I use yarn/pnpm so I'm safe" | All package managers resolve from the same npm registry. Same bad packages. |

### What "Looks Clean" But Isn't Enough

- **package.json shows `^1.13.0`**: The range includes 1.14.1. If your lockfile resolved to it, you're hit
- **node_modules is deleted**: Good for future, but past execution already exfiltrated
- **You updated to a clean version**: Same — past damage is done
- **`npm audit` says clean**: npm audit checks for advisories, not real-time IOC scanning
- **No alerts from GitHub Dependabot**: Dependabot may lag behind emerging supply chain attacks

### Exposure vs Compromise

**EXPOSURE** = the bad version appears in your dependency tree (lockfile, package.json range)
- This means you COULD be compromised
- Requires investigation to determine if code actually executed

**COMPROMISE** = the malicious code actually ran on a machine
- This means credentials are STOLEN
- Requires full secret rotation, not just package removal

The distinction matters because exposure without execution (e.g., lockfile was committed but no install ran on that machine) is a near-miss, not a breach. But the bar for "execution happened" is very low — a single `npm install` is enough.

### Where Normal Teams Fail

1. **They treat it as a package update, not an incident.** Remove bad version, move on. Wrong.
2. **They rotate some secrets but not all.** The malware harvests EVERYTHING in the environment.
3. **They forget CI/CD.** CI runners had secrets. Those secrets are compromised.
4. **They don't check other machines.** Developer laptops, staging servers, preview deployments.
5. **They don't preserve evidence.** Delete node_modules before forensics. Lose the postinstall artifacts.
6. **They don't check transitive dependencies.** Only look at direct deps in package.json.
7. **They assume the attack is over.** Stolen credentials may be used days/weeks later.

---

## PHASE 2 — INCIDENT RESPONSE PLAYBOOK

### Triage Severity Model

| Level | Criteria | Response Time |
|---|---|---|
| **P0 — Active Compromise** | Malicious package installed AND executed (postinstall ran). CI/CD pipelines affected. | Immediate. Drop everything. |
| **P1 — Confirmed Exposure** | Bad version resolved in lockfile. `npm install` was run during exposure window. | Within 1 hour |
| **P2 — Possible Exposure** | Version range could resolve to bad version but lockfile shows clean version | Within 4 hours |
| **P3 — No Exposure** | No matching packages in tree. Axios pinned to safe version. | Verify and document. No emergency. |

### Exposure vs Compromise Decision Tree

```
START: Does your project use axios (directly or transitively)?
  |
  NO → P3. Verify with: grep -r "axios" package-lock.json yarn.lock
  |
  YES → Does your lockfile resolve to 1.14.1 or 0.30.4?
    |
    NO → P3. Your lockfile is clean. Monitor for new compromised versions.
    |
    YES → Was `npm install` / `yarn install` / `pnpm install` run
          while the lockfile had the bad version?
      |
      UNKNOWN → Treat as YES (assume compromise)
      |
      NO → P2. Lockfile exposure only. Update lockfile. No secret rotation needed.
      |
      YES → Was it run on:
        |
        Developer machine → P1. Rotate local secrets. Check what env vars were present.
        |
        CI/CD pipeline → P0. Rotate ALL CI secrets. Review build logs. Check deployments.
        |
        Production server → P0. Rotate ALL production secrets. Check for lateral movement.
```

### Immediate Containment Actions (First 30 Minutes)

```bash
# 1. Identify exposure across all repos (run from org root or for each repo)
grep -r '"axios"' */package-lock.json */yarn.lock 2>/dev/null | grep -E '1\.14\.1|0\.30\.4'
grep -r '"plain-crypto-js"' */package-lock.json */yarn.lock 2>/dev/null

# 2. Block the bad versions in .npmrc (per-project or global)
echo "//registry.npmjs.org/:_authToken=\${NPM_TOKEN}" >> .npmrc
# Add to CI: npm config set //registry.npmjs.org/:_authToken ""  (rotate first)

# 3. Pin axios in package.json to last known good version
npm install axios@1.13.0 --save-exact

# 4. Clear npm cache on affected machines
npm cache clean --force

# 5. Delete node_modules and reinstall from clean lockfile
rm -rf node_modules
# Update lockfile to remove bad versions first
npm install

# 6. If CI is affected: disable pipelines until secrets are rotated
# GitHub Actions: Settings → Secrets → rotate ALL
# GitLab: Settings → CI/CD → Variables → rotate ALL
```

### Repo Investigation

```bash
# Check lockfile history for when bad version was introduced
git log -p --all -S '"axios": "1.14.1"' -- package-lock.json
git log -p --all -S '"plain-crypto-js"' -- package-lock.json

# Check all branches, not just main
for branch in $(git branch -r | grep -v HEAD); do
  echo "=== $branch ==="
  git show "$branch:package-lock.json" 2>/dev/null | grep -E 'axios|plain-crypto' || echo "clean"
done

# Check if lockfile was committed with bad version
git log --oneline --all -- package-lock.json | head -20

# Determine exposure window
git log --format="%H %ci" --all -S '"1.14.1"' -- package-lock.json
```

### Host Investigation

```bash
# Check npm install history
ls -la ~/.npm/_logs/ | tail -20
grep -r "axios" ~/.npm/_logs/*.log 2>/dev/null
grep -r "plain-crypto" ~/.npm/_logs/*.log 2>/dev/null

# Check if bad package exists in cache
find ~/.npm/_cacache -name "*.tgz" 2>/dev/null | xargs -I{} tar -tzf {} 2>/dev/null | grep plain-crypto

# Check global installs
npm list -g --depth=0 2>/dev/null | grep -E 'axios|plain-crypto'

# Check for exfiltration artifacts
find /tmp -name ".crypto-cache" -o -name "crypto-*.log" 2>/dev/null
find /var/tmp -name ".crypto-cache" -o -name "crypto-*.log" 2>/dev/null

# Check shell history for C2 domains
grep -E "cryptopackage\.net|npm-stats\.org" ~/.bash_history ~/.zsh_history 2>/dev/null

# Check DNS cache (macOS)
log show --predicate 'process == "mDNSResponder"' --last 24h | grep -E "cryptopackage|npm-stats"

# Check network connections
lsof -i -n -P | grep -i node
netstat -an | grep -E "ESTABLISHED|SYN_SENT" | grep -v "127.0.0.1"
```

### CI/CD Investigation

```bash
# GitHub Actions: check recent workflow runs
gh run list --limit 50 --json name,conclusion,createdAt

# Check if CI installed during exposure window
# Look at workflow logs for npm install output
gh run view <run-id> --log | grep -E "axios|plain-crypto"

# Check CI environment for exposed secrets
# List all repository secrets (names only, not values)
gh secret list

# Check deploy keys
gh deploy-key list

# Check GitHub Apps with access
gh api /repos/{owner}/{repo}/installations
```

### Credential Rotation Scope

If compromise is confirmed, rotate **ALL** of the following:

**Immediate (within 1 hour):**
- [ ] npm tokens (`NPM_TOKEN`, `NPM_AUTH_TOKEN`)
- [ ] GitHub tokens (`GH_TOKEN`, `GITHUB_TOKEN`)
- [ ] AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
- [ ] CI/CD pipeline secrets (ALL of them, not just the ones you think were exposed)

**Within 4 hours:**
- [ ] Database connection strings (`DATABASE_URL`, `MONGODB_URI`, `REDIS_URL`)
- [ ] Payment processors (`STRIPE_SECRET_KEY`, `STRIPE_API_KEY`)
- [ ] Communication APIs (`SENDGRID_API_KEY`, `TWILIO_AUTH_TOKEN`, `SLACK_TOKEN`)
- [ ] Cloud provider service accounts (GCP, Azure)
- [ ] Docker registry credentials
- [ ] SSH keys if they were in environment variables

**Within 24 hours:**
- [ ] API keys for all third-party services
- [ ] Internal service-to-service auth tokens
- [ ] Any secret that was EVER in an environment variable on an affected machine/CI runner
- [ ] OAuth client secrets
- [ ] Encryption keys if stored in env vars

### Rebuild/Reimage Criteria

**Reimage the machine if:**
- Malicious postinstall script confirmed to have executed
- Unknown processes found running
- Persistence mechanisms detected (cron jobs, launch agents, systemd services)
- Network IOC domains found in DNS/connection logs
- Machine handles production secrets

**Clean reinstall sufficient if:**
- Only lockfile exposure, no confirmed install execution
- No suspicious artifacts found
- No credential exposure confirmed

### Evidence Preservation

Before cleanup, preserve:

```bash
# Create evidence directory
mkdir -p ~/incident-evidence/$(date +%Y%m%d)

# Save lockfiles
cp package-lock.json yarn.lock pnpm-lock.yaml ~/incident-evidence/$(date +%Y%m%d)/ 2>/dev/null

# Save node_modules bad packages (if present)
tar czf ~/incident-evidence/$(date +%Y%m%d)/malicious-packages.tar.gz \
  node_modules/plain-crypto-js \
  node_modules/axios/package.json \
  2>/dev/null

# Save npm logs
cp -r ~/.npm/_logs ~/incident-evidence/$(date +%Y%m%d)/npm-logs/ 2>/dev/null

# Save shell history
cp ~/.bash_history ~/.zsh_history ~/incident-evidence/$(date +%Y%m%d)/ 2>/dev/null

# Save process list
ps aux > ~/incident-evidence/$(date +%Y%m%d)/processes.txt

# Save network state
lsof -i -n -P > ~/incident-evidence/$(date +%Y%m%d)/network.txt 2>/dev/null
netstat -an > ~/incident-evidence/$(date +%Y%m%d)/netstat.txt 2>/dev/null

# Save environment (redact values)
env | sed 's/=.*/=REDACTED/' > ~/incident-evidence/$(date +%Y%m%d)/env-keys.txt
```

### Recovery and Validation

```bash
# 1. Clean lockfile
rm -rf node_modules package-lock.json
npm install axios@1.13.0 --save-exact  # or latest known-good
npm install

# 2. Verify clean
grep "plain-crypto" package-lock.json  # should return nothing
grep "1.14.1\|0.30.4" package-lock.json | grep axios  # should return nothing

# 3. Run supply-chain-defender
python -m scd scan-repo .

# 4. Verify all rotated credentials work
# (test each service with new credentials)

# 5. Monitor for unauthorized access
# Check AWS CloudTrail, GitHub audit log, npm access logs
# for use of old (now-rotated) credentials
```

### Postmortem Improvements

1. **Pin exact versions** in package.json (no `^` or `~`)
2. **Use `npm ci`** in CI instead of `npm install` (respects lockfile strictly)
3. **Add lockfile integrity checks** to CI pipeline
4. **Set up `supply-chain-defender`** as a CI step
5. **Use `.npmrc` to configure** `ignore-scripts=true` for untrusted packages
6. **Implement Corepack** for package manager version pinning
7. **Enable npm provenance** verification where available
8. **Review and minimize** CI secret exposure — use short-lived tokens
9. **Set up alerts** for new transitive dependency additions
10. **Document the incident** with timeline, impact assessment, and remediation steps
