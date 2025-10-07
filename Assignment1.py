
LOGFILE = "sample_auth_small.log"  # change filename if needed

import json
from collections import defaultdict
from datetime import datetime

LOGFILE = "sample_auth_small.log"

def parse_auth_line(line):
    """
    Parse an auth log line and return (timestamp, ip, event_type)
    Example auth line:
    Mar 10 13:58:01 host1 sshd[1023]: Failed password for invalid user admin from 203.0.113.45 port 52344 ssh2
    We will:
     - parse timestamp (assume year 2025)
     - extract IP (token after 'from')
     - event_type: 'failed' if 'Failed password', 'accepted' if 'Accepted password', else 'other'
    """
    parts = line.split()
    # timestamp: first 3 tokens 'Mar 10 13:58:01'
    ts_str = " ".join(parts[0:3])
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        ts = None
    ip = None
    event_type = "other"
    if "Failed password" in line:
        event_type = "failed"
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted"
    if " from " in line:
        try:
            idx = parts.index("from")
            ip = parts[idx+1]
        except (ValueError, IndexError):
            ip = None
    return ts, ip, event_type

if __name__ == "__main__":
    per_ip_timestamps = defaultdict(list)
    with open(LOGFILE) as f:
        for line in f:
            ts, ip, event = parse_auth_line(line)
            if ts and ip and event == "failed":   # checks that ts and ip are not null, and that event=="failed"
                per_ip_timestamps[ip].append(ts)
    # quick print
    for ip, times in per_ip_timestamps.items():
        print(ip, len(times))


count = 0
with open ("sample_auth_small.log", "r") as f:
    for line in f:
        count += 1
print("Lines read:", count)

# Convert to a set to remove duplicates
unique_ips = set()
count_uni = 0
firstTen = 0

## This is the main block that will run first. 
## It will call any functions from above that we might need.
if __name__ == "__main__":
    with open(LOGFILE, "r") as f:
        for line in f:
            ip = parse_auth_line(line.strip())
            if ip:
                unique_ips.add(ip)

for ip in unique_ips:
    count_uni += 1

print("Unique IPs:", count_uni)

            
from collections import defaultdict

counts = defaultdict(int)           # Create a dictionary to keep track of IPs

with open("sample_auth_small.log") as f:
    for line in f:
        if "Failed password" in line:
            # extract ip
            ip = parse_auth_line(line)
            if ip:
                counts[ip] += 1

for ip, count in counts.items():
    print(f"Failed login attempt(s) from {ip}" + f" There was {count}" + " login attempt(s)")

from datetime import timedelta

incidents = []
window = timedelta(minutes=10)
for ip, times in parse_auth_line.items():
    times.sort()
    n = len(times)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and (times[j+1] - times[i]) <= window:
            j += 1
        count = j - i + 1
        if count >= 5:
            incidents.append({
                "ip": ip,
                "count": count,
                "first": times[i].isoformat(),
                "last": times[j].isoformat()
            })
            # advance i past this cluster to avoid duplicate overlapping reports:
            i = j + 1
        else:
            i += 1