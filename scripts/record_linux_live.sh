#!/usr/bin/env bash
# Record Linux telemetry on an ephemeral GitHub Actions runner ONLY (needs sudo).
#
#   benign/     auditd + Sysmon for Linux during an ordinary dev workload
#               (pip install, the unit-test suite, git): the false-positive corpus
#   emulation/  the same sensors while a few benign discovery-style commands run
#               (whoami, id, uname, crontab -l, base64 of a dummy file, curl to
#               127.0.0.1). No third-party host is contacted, nothing is persisted.
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
sudo auditctl -D >/dev/null
sudo auditctl -a always,exit -F arch=b64 -S execve -k exec
sudo auditctl -a always,exit -F arch=b64 -S connect -k net
sudo auditctl -w /etc/passwd -p r -k passwd_read
sudo auditctl -w /etc/crontab -p wa -k cron

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
  sudo ausearch --raw -ts "$(date -d "@$2" '+%x %T')" > "$1/auditd.log" 2>/dev/null || true
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
lsmod >/dev/null; ps aux >/dev/null; ip a >/dev/null; find /tmp -name 'anvil_dummy*' >/dev/null
rm -f /tmp/anvil_dummy.txt /tmp/anvil_dummy2
sleep 3
dump "$OUT/emulation" "$T2"
