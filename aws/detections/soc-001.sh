#!/usr/bin/env bash
set -euo pipefail
umask 077


base="$HOME/cloud-soc"
state_dir="$base/state"
alerts_dir="$base/alerts"
alert_log="$alerts_dir/soc-001.log"

mkdir -p "$state_dir" "$alerts_dir"
chmod 700 "$state_dir" "$alerts_dir"
touch "$alert_log"
chmod 600 "$alert_log"

if ! entries=$(sudo journalctl -t cloud-soc-sim \
    --since "5 minutes ago" --no-pager -o cat); then
    echo "ERROR: Could not read system journal." >&2
    exit 1
fi

pattern='^SIMULATED Failed password for invalid user [^ ]+ from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) port [0-9]+ ssh2$'

declare -A counts=()

while IFS= read -r line; do
    if [[ $line =~ $pattern ]]; then
        ip=${BASH_REMATCH[1]}
        counts["$ip"]=$(( ${counts["$ip"]:-0} + 1 ))
    fi
done <<< "$entries"

now=$(date -u +%s)
new_alerts=0

for ip in "${!counts[@]}"; do
    count=${counts["$ip"]}
    (( count >= 5 )) || continue

    state_file="$state_dir/$ip.last"
    last_alert=0

    if [[ -f $state_file ]]; then
        last_alert=$(cat "$state_file")
        [[ $last_alert =~ ^[0-9]+$ ]] || last_alert=0
    fi

    if (( now - last_alert < 300 )); then
        echo "Duplicate suppressed for $ip"
        continue
    fi

    {
        printf '===== SOC-001 %s =====\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'ALERT [SOC-001]: Repeated simulated SSH failures!\n'
        printf 'Source IP: %s\nFailed attempts: %s\n' "$ip" "$count"
        printf 'Severity: MEDIUM (LAB SIMULATION)\n'
    } | tee -a "$alert_log"

    printf '%s\n' "$now" > "$state_file"
    chmod 600 "$state_file"
    new_alerts=$((new_alerts + 1))
done

if (( new_alerts == 0 )); then
    echo "No new alerts."
fi
