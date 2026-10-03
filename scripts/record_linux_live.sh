#!/usr/bin/env bash
# Record Linux telemetry on an ephemeral GitHub Actions runner ONLY (needs sudo).
#
#   benign/     auditd + Sysmon for Linux during an ordinary dev workload
#               (pip install, the unit-test suite, git): the false-positive corpus
#   emulation/  the same sensors while a few benign discovery-style commands run.
#               No third-party host is contacted, nothing is persisted, every file
#               touched is a dummy under /tmp. Each command is labelled with the
#               ATT&CK technique it resembles (written to emulation/window.txt):
#                 whoami, id                        T1033  system owner/user discovery
#                 uname -a, hostname, os-release,   T1082  system information discovery
#                 lsmod
#                 crontab -l                        T1007  system service discovery
#                 cat /etc/passwd                   T1087.001  local account discovery
#                 base64 of a dummy file            T1027  obfuscated files or information
#                 ps aux                            T1057  process discovery
#                 ip a                              T1016  system network configuration discovery
#                 find /tmp -maxdepth 1             T1083  file and directory discovery
#               (curl to 127.0.0.1:9 and a cp of /etc/hostname to /tmp are unlabelled noise.)
#
# Output: $ANVIL_DATA/linux-live/{benign,emulation}/*.log (+ window.txt).
set -euo pipefail
if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
  echo "refusing to run outside a GitHub Actions runner" >&2
  exit 2
fi
OUT="${ANVIL_DATA:?}/linux-live"
mkdir -p "$OUT/benign" "$OUT/emulation"

sudo apt-get install -y -qq auditd >/dev/null
# Make sure the daemon is running *before* the rules are added: starting auditd loads
# /etc/audit/audit.rules, which begins with -D and would delete rules added earlier.
sudo systemctl restart auditd 2>/dev/null || sudo service auditd restart
sudo auditctl -D >/dev/null
sudo auditctl -a always,exit -F arch=b64 -S execve -k exec
sudo auditctl -a always,exit -F arch=b64 -S connect -k net
sudo auditctl -w /etc/passwd -p r -k passwd_read
sudo auditctl -w /etc/crontab -p wa -k cron
sudo auditctl -e 1 >/dev/null
sudo auditctl -s

SYSMON=0
if . /etc/os-release && wget -q "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/packages-microsoft-prod.deb" -O /tmp/pmp.deb \
   && sudo dpkg -i /tmp/pmp.deb >/dev/null && sudo apt-get update -qq && sudo apt-get install -y -qq sysmonforlinux >/dev/null; then
  cat > /tmp/sysmon.xml <<'XML'
<Sysmon schemaversion="4.81"><EventFiltering>
  <ProcessCreate onmatch="exclude"/>
  <NetworkConnect onmatch="exclude"/>
  <FileCreate onmatch="exclude"/>
</EventFiltering></Sysmon>
XML
  sudo sysmon -accepteula -i /tmp/sysmon.xml >/dev/null && SYSMON=1
fi
echo "sysmon for linux: $SYSMON"

dump() {  # $1=dir $2=start-epoch
  # Raw audit records from the daemon's log, selected by their own epoch timestamp
  # (msg=audit(<epoch>.<ms>:<serial>)), so no locale-dependent ausearch -ts parsing.
  sudo python3 - "$2" /var/log/audit/audit.log > "$1/auditd.log" <<'PY'
import re
import sys

t0 = int(sys.argv[1])
rx = re.compile(r"msg=audit\((\d+)\.")
with open(sys.argv[2], errors="replace") as fh:
    for line in fh:
        m = rx.search(line)
        if m and int(m.group(1)) >= t0:
            sys.stdout.write(line)
PY
  if [ "$SYSMON" = 1 ]; then
    sudo journalctl -t sysmon -o cat --since "@$2" | grep '^<Event>' > "$1/sysmon_linux.log" || true
  fi
  sudo chown -R "$(id -u)" "$1"
  wc -l "$1"/*.log
}

# ---- benign window: an ordinary developer workload
T0=$(date +%s)
python -m venv /tmp/wl && /tmp/wl/bin/pip install -q -e ".[dev]" && /tmp/wl/bin/python -m pytest -q -x tests >/dev/null || true
git log --oneline -n 50 >/dev/null; git status >/dev/null; ls -la /etc >/dev/null; df -h >/dev/null
sleep 5
T1=$(date +%s)
dump "$OUT/benign" "$T0"
printf 'seconds=%s\nworkload=venv + pip install + pytest + git on the runner\n' "$((T1 - T0))" > "$OUT/benign/window.txt"

# ---- emulation window: benign commands only
T2=$(date +%s)
whoami; id; uname -a; hostname; cat /etc/os-release >/dev/null
crontab -l 2>/dev/null || true
cat /etc/passwd >/dev/null
echo "dummy" > /tmp/anvil_dummy.txt && base64 /tmp/anvil_dummy.txt >/dev/null && cp /etc/hostname /tmp/anvil_dummy2
curl -s -m 2 http://127.0.0.1:9/ >/dev/null || true
lsmod >/dev/null; ps aux >/dev/null; ip a >/dev/null
find /tmp -maxdepth 1 -name 'anvil_dummy*' >/dev/null 2>&1 || true
rm -f /tmp/anvil_dummy.txt /tmp/anvil_dummy2
sleep 3
T3=$(date +%s)
dump "$OUT/emulation" "$T2"
printf 'seconds=%s\nworkload=benign discovery-style commands (see scripts/record_linux_live.sh)\ntechniques=T1033,T1082,T1007,T1087.001,T1027,T1057,T1016,T1083\n' \
  "$((T3 - T2))" > "$OUT/emulation/window.txt"
