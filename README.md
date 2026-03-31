# Supply Chain Defender

Multi-ecosystem supply chain attack detection and response tool. Built same-day as the axios npm compromise to provide immediate detection and triage tooling for affected teams.

## Axios Compromise — 2026-03-31 (Today)

**Advisory:** [GHSA-fw8c-xr5c-95f9](https://github.com/advisories/GHSA-fw8c-xr5c-95f9) | MAL-2026-2306 | SNYK-JS-AXIOS-15850650

| | |
|---|---|
| **Attack window** | 2026-03-31 00:21 UTC – 03:29 UTC |
| **Vector** | Hijacked npm account (`jasonsaayman`), malicious postinstall RAT |
| **Malicious packages** | `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.1` |
| **Safe axios versions** | `<=1.14.0` or `>=1.14.2` (latest: `1.9.0`) |
| **C2 endpoint** | `sfrclak.com:8000` / `142.11.206.73:8000` |
| **Payload** | Cross-platform credential-harvesting RAT with self-destruct |
| **Status** | Both packages removed from npm; security placeholders published |

If you ran `npm install` between 00:21–03:29 UTC today and your lockfile resolved to `axios@1.14.1` or `axios@0.30.4`, **treat this as a confirmed breach** and rotate all secrets immediately.

→ Full incident response procedure: [docs/incident_playbook.md](docs/incident_playbook.md)

## Quick Start

```bash
# Install
pip install -e .

# Scan a repo
scd scan-repo /path/to/your/project

# Scan this host for IOCs
scd scan-host

# CI mode (strict, fails on any finding)
scd ci-guard /path/to/project --strict

# JSON output
scd scan-repo . --format json --output report.json
```

## What It Does

### Scan Modes

| Mode | What It Checks |
|---|---|
| `scan-repo` | All ecosystems: npm/yarn/pnpm lockfiles, Python (requirements, Pipfile, poetry), Go modules, Cargo, Ruby gems, NuGet, Maven/Gradle, Dockerfiles, GitLab CI, Jenkinsfiles |
| `scan-host` | npm cache, global installs, temp dirs, npm logs, shell history, env vars, network IOCs |
| `ci-guard` | Same as scan-repo but with CI-appropriate exit codes and strict mode |
| `sbom` | Generate CycloneDX 1.5 SBOM from any repo |

### Ecosystem Support

`npm` · `yarn` · `pnpm` · `Python/pip` · `Go modules` · `Rust/Cargo` · `Ruby/Bundler` · `NuGet` · `Maven` · `Gradle` · `Docker` · `GitLab CI` · `Jenkins`

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | Clean — no findings |
| 1 | Warnings — LOW/MEDIUM findings only |
| 2 | Compromised — HIGH/CRITICAL findings |
| 3 | Error — scanner failed |

### Detection Tiers

**Tier 1 (Deterministic)**: Exact package name + version match against IOC database. Zero false positives.

**Tier 2 (Heuristic)**: Suspicious package name patterns, unexpected transitive dependencies. Moderate false positive rate — requires human review.

## Architecture

```
CLI → ScanContext → [RepoScanner, LockfileScanner, NodeModulesScanner, HostScanner, IOCScanner]
                          ↓
                    list[Finding]
                          ↓
                     ScanResult
                          ↓
                  Reporter (JSON | Terminal)
                          ↓
                      Exit Code
```

### Scanners

- **RepoScanner**: Scans package.json for known-bad dependencies and suspicious patterns
- **LockfileScanner**: Parses package-lock.json, yarn.lock, pnpm-lock.yaml for exact resolved versions
- **NodeModulesScanner**: Walks installed packages, checks for postinstall execution evidence
- **HostScanner**: Platform-specific scan of npm cache, global installs, temp dirs, logs
- **IOCScanner**: Network IOCs (DNS, connections), filesystem artifacts, persistence mechanisms

### IOC Database

IOC definitions in `scd/iocs/axios_compromise.json`. Adding a new attack requires only a new JSON file — no code changes.

### Policy System

Configurable blocklists, allowlists, and CI options in `scd/policies/default_policy.json`. Override with `--policy custom.json`.

## Documentation

- [Incident Playbook](docs/incident_playbook.md) — Full IR procedure
- [Platform IOCs](docs/platform_iocs.md) — macOS/Linux/Windows detection commands
- [CI Integration](docs/ci_integration.md) — GitHub Actions setup, lockfile gates, defense layers

## Hardening Roadmap

### 24-Hour Plan
1. Run `scd scan-repo .` on all active repos
2. Run `scd scan-host` on all developer machines and CI runners
3. If findings: follow incident playbook immediately
4. Pin axios to exact safe version in all package.json files
5. Add `scd ci-guard` to CI pipelines
6. Rotate any potentially exposed credentials

### 7-Day Plan
1. Audit all npm dependencies for exact version pinning
2. Set `ignore-scripts=true` in project .npmrc files
3. Implement lockfile diff gates in PR workflows
4. Review and minimize CI secret exposure
5. Set up daily scheduled scans (GitHub Actions cron)
6. Document incident response contacts and procedures
7. Train team on supply-chain attack indicators

### 30-Day Plan
1. Implement npm provenance verification
2. Set up internal npm registry/proxy with package allowlisting
3. Add automated new-dependency review workflow
4. Implement SBOM generation and monitoring
5. Establish recurring dependency audit schedule
6. Evaluate package signing and verification tools
7. Build runbook for future supply-chain incidents
8. Conduct tabletop exercise with the team

## Gap Analysis

### What This Tool Catches Well
- Exact known-bad package name + version matches (zero false negatives for known threats)
- Suspicious package name patterns (typosquatting)
- Lockfile exposure across all major formats (npm, yarn, pnpm)
- Installed malicious packages in node_modules
- Host-level artifacts from known attacks
- Environment variable exposure assessment
- Policy violations from custom blocklists

### What It Misses
- **Zero-day attacks**: Packages not yet in the IOC database
- **Obfuscated payloads**: Malicious code hidden in legitimate-looking packages
- **Registry-level attacks**: Content substitution without version changes
- **Time-delayed payloads**: Malicious code that only activates after a delay
- **Conditional payloads**: Code that only runs in specific environments
- **Build-time injection**: Attacks that modify build output without changing source
- **Native module compromise**: Malicious code in compiled native addons

### Where Human DFIR Is Still Required
- Determining blast radius of confirmed compromise
- Analyzing obfuscated malicious payloads
- Correlating exfiltration with credential usage
- Investigating lateral movement from stolen credentials
- Legal/compliance notification decisions
- Determining if stolen credentials were actually used
- Forensic analysis of custom/novel attack techniques

### What Would Be Needed for Enterprise Grade
- Real-time npm registry monitoring (publish event webhooks)
- Integration with SIEM/SOAR platforms
- Automated credential rotation via vault integration
- Package behavioral analysis (sandbox execution)
- Machine learning for anomaly detection in dependency graphs
- Integration with vulnerability databases (OSV, NVD)
- Multi-tenant support with centralized IOC management
- Signed IOC database updates
- SLA-backed IOC update pipeline
- Compliance reporting (SOC2, ISO 27001)

## Development

```bash
pip install -e ".[dev]"
pytest tests/
```

## License

MIT
