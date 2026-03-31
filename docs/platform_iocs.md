# Platform-Specific IOC Detection Guide

## macOS

### Known IOC Paths

```
~/.npm/                              # npm cache root
~/.npm/_cacache/                     # Package content cache
~/.npm/_logs/                        # npm install logs
/opt/homebrew/lib/node_modules/      # Homebrew global npm (Apple Silicon)
/usr/local/lib/node_modules/         # Legacy global npm
~/.nvm/versions/node/*/lib/node_modules/  # nvm-managed globals
/tmp/                                # System temp
$TMPDIR                              # User-specific temp (often /var/folders/...)
~/Library/Caches/                    # macOS application caches
```

### Suspicious Temp/Cache Locations

```
$TMPDIR/.crypto-cache               # Dropped by plain-crypto-js
$TMPDIR/crypto-*.log                # Staging file for exfiltrated data
~/Library/Caches/npm/               # Alternate npm cache
/private/var/folders/*/*/T/          # macOS per-user temp (resolves from $TMPDIR)
```

### Quick Validation Commands

```bash
# Check if bad packages were ever installed
find ~/.npm -name "package.json" -exec grep -l "plain-crypto-js" {} \; 2>/dev/null
npm cache ls 2>/dev/null | grep -E "axios.*1\.14\.1|axios.*0\.30\.4|plain-crypto"

# Check npm logs for install evidence
grep -r "plain-crypto\|axios@1.14.1\|axios@0.30.4" ~/.npm/_logs/ 2>/dev/null

# Check DNS resolution history
log show --predicate 'process == "mDNSResponder"' --last 7d --style compact 2>/dev/null | grep -E "cryptopackage|npm-stats"

# Check for dropped artifacts
find /tmp "$TMPDIR" ~/Library/Caches -name ".crypto-cache" -o -name "crypto-*.log" 2>/dev/null

# Check LaunchAgents for persistence
ls ~/Library/LaunchAgents/ | grep -i crypto
grep -r "cryptopackage\|npm-stats\|plain-crypto" ~/Library/LaunchAgents/ 2>/dev/null

# Check for active node processes connecting to IOC domains
lsof -i -n -P | grep node | grep -v "127.0.0.1\|::1"

# Check for unusual outbound connections
nettop -P -L 1 | grep node 2>/dev/null
```

### Strong Evidence (high confidence of compromise)

- `plain-crypto-js` found in `node_modules/` on disk
- npm log entries showing `plain-crypto-js@4.2.1` being installed
- DNS resolution of `cryptopackage.net` or `npm-stats.org` in system logs
- `.crypto-cache` file in temp directory
- `crypto-*.log` files in temp directory with encoded data
- Active network connections from node process to unknown IPs

### Weak Evidence (warrants investigation, not conclusive)

- `axios@1.14.1` in lockfile but no node_modules on disk (may have been cleaned)
- npm cache contains axios tarballs (could be any version — verify content)
- Shell history contains `npm install` during exposure window
- `^1.14.0` range in package.json (could resolve to 1.14.1 but might not have)

### Response Guidance

1. **If strong evidence found**: Treat as P0. Rotate all credentials accessible from this machine. Preserve evidence. Consider reimaging.
2. **If weak evidence only**: Treat as P1. Investigate further. Check all repos cloned on this machine. Check if `npm install` was run during exposure window.
3. **If clean**: Document verification steps taken. Add `scd scan-host` to periodic checks.

---

## Linux

### Known IOC Paths

```
~/.npm/                              # npm cache root
~/.npm/_cacache/                     # Package content cache
~/.npm/_logs/                        # npm install logs
/usr/lib/node_modules/               # System global npm
/usr/local/lib/node_modules/         # Local global npm
~/.nvm/versions/node/*/lib/node_modules/  # nvm-managed globals
~/.local/share/                      # XDG data directory
/tmp/                                # System temp
/var/tmp/                            # Persistent temp
~/.cache/                            # XDG cache directory
```

### Suspicious Temp/Cache Locations

```
/tmp/.crypto-cache
/tmp/crypto-*.log
/var/tmp/.crypto-cache
/var/tmp/crypto-*.log
~/.cache/.crypto-cache
/dev/shm/                            # Shared memory — sometimes used to avoid disk forensics
```

### Quick Validation Commands

```bash
# Check if bad packages were ever installed
find ~/.npm -name "package.json" -exec grep -l "plain-crypto-js" {} \; 2>/dev/null

# Check npm logs
grep -r "plain-crypto\|axios@1.14.1\|axios@0.30.4" ~/.npm/_logs/ 2>/dev/null

# Check for dropped artifacts
find /tmp /var/tmp ~/.cache -name ".crypto-cache" -o -name "crypto-*.log" 2>/dev/null

# Check systemd for persistence
systemctl --user list-units | grep -i crypto
find ~/.config/systemd/user/ -exec grep -l "crypto\|npm-stats" {} \; 2>/dev/null

# Check crontab
crontab -l 2>/dev/null | grep -E "node|npm|crypto"
cat /etc/cron.d/* 2>/dev/null | grep -E "node|npm|crypto"

# Check active connections
ss -tnp | grep node
lsof -i -n -P | grep node

# Check DNS queries (if systemd-resolved is used)
resolvectl query cryptopackage.net 2>/dev/null
journalctl -u systemd-resolved --since "7 days ago" 2>/dev/null | grep -E "cryptopackage|npm-stats"

# Docker-specific: check if containers ran the bad version
docker ps -a --format "{{.Names}}" | xargs -I{} docker exec {} grep -r "plain-crypto" /app/node_modules/ 2>/dev/null
```

### Strong Evidence

Same as macOS, plus:
- Systemd service or timer referencing IOC domains
- `/dev/shm/` contains crypto-related artifacts
- Docker container volumes containing `plain-crypto-js`

### Weak Evidence

Same as macOS, plus:
- CI runner workspace directories with traces
- Docker build cache containing bad package layers

### Response Guidance

Same severity model as macOS. Additionally:
- **For CI runners (GitHub Actions, GitLab, Jenkins)**: Assume all secrets accessible during the run are compromised
- **For Docker builds**: Check if the build pushed images containing the malicious code to any registry
- **For production servers**: Immediately rotate secrets and check application logs for unusual outbound connections

---

## Windows

### Known IOC Paths

```
%APPDATA%\npm\                           # npm global root
%APPDATA%\npm\node_modules\              # Global packages
%APPDATA%\npm-cache\                     # npm cache
%LOCALAPPDATA%\npm-cache\                # Alternate cache location
%USERPROFILE%\.npm\                       # Home-based npm dir
%USERPROFILE%\.npm\_cacache\              # Package content cache
%USERPROFILE%\.npm\_logs\                 # npm logs
%NVM_HOME%\                              # nvm-windows installs
C:\Program Files\nodejs\node_modules\    # System Node.js
```

### Suspicious Temp/Cache Locations

```
%TEMP%\.crypto-cache
%TEMP%\crypto-*.log
%LOCALAPPDATA%\Temp\.crypto-cache
%LOCALAPPDATA%\Temp\crypto-*.log
```

### Quick Validation Commands

```powershell
# Check if bad packages were ever installed
Get-ChildItem -Path "$env:USERPROFILE\.npm" -Recurse -Filter "package.json" |
  Select-String "plain-crypto-js" 2>$null

# Check npm logs
Get-ChildItem -Path "$env:USERPROFILE\.npm\_logs" -Filter "*.log" |
  Select-String "plain-crypto|axios@1.14.1|axios@0.30.4" 2>$null

# Check for dropped artifacts
Get-ChildItem -Path $env:TEMP -Filter ".crypto-cache" -Recurse 2>$null
Get-ChildItem -Path $env:TEMP -Filter "crypto-*.log" -Recurse 2>$null

# Check Task Scheduler for persistence
schtasks /query /fo LIST | findstr /i "crypto npm-stats"

# Check active connections
netstat -ano | findstr "ESTABLISHED" | findstr /v "127.0.0.1"
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} |
  Select-Object LocalAddress,RemoteAddress,RemotePort,OwningProcess

# Check if node is making connections
Get-Process node -ErrorAction SilentlyContinue |
  ForEach-Object { Get-NetTCPConnection -OwningProcess $_.Id -ErrorAction SilentlyContinue }

# Check DNS cache
Get-DnsClientCache | Where-Object {$_.Entry -match "cryptopackage|npm-stats"}

# Check Startup registry keys
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" 2>$null |
  Select-String "crypto|npm-stats" 2>$null
```

### Strong Evidence

Same as macOS/Linux, adapted for Windows paths:
- `plain-crypto-js` in any `node_modules` directory
- npm logs referencing the malicious packages
- DNS cache entries for IOC domains
- Temp directory artifacts
- Task Scheduler entries with suspicious commands
- Registry Run keys referencing node/npm with IOC-related arguments

### Weak Evidence

Same as macOS/Linux, adapted for Windows paths

### Response Guidance

Same severity model. Windows-specific additions:
- Check Windows Event Log for process creation events
- Check PowerShell history: `Get-Content (Get-PSReadlineOption).HistorySavePath`
- For machines managed by AD/SCCM: alert IT to check for lateral movement
- Check Windows Defender logs for any flagged activities
