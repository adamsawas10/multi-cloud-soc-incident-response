# SOC-001: Simulated SSH Brute-Force Detection

This directory contains a Bash-based detection prototype developed
on Ubuntu Linux.

The script analyzes simulated SSH authentication failures recorded
in the systemd journal under the `cloud-soc-sim` tag.

It counts matching events by source IPv4 address within a five-minute
lookback window and generates an alert when five or more failures
are observed. A five-minute cooldown suppresses repeated alerts
for the same IP address.

This script is a manually executed lab prototype. It is separate
from the production-style CloudWatch metric filter used to detect
actual SSH authentication failures in the AWS environment.
