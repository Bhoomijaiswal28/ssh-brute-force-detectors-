# detector.py
# SSH log padhke brute-force attacks pakadta hai.
import csv
import re
import sys
from collections import defaultdict
from datetime import datetime

LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
THRESHOLD = 5        # itne fail...
WINDOW_SECONDS = 60  # ...itne seconds ke andar = alert
YEAR = 2026          # syslog mein saal nahi hota

FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8}) .*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
)
ACCEPTED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8}) .*Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)"
)

def parse_time(text):
    return datetime.strptime(f"{YEAR} {text}", "%Y %b %d %H:%M:%S")

fails = defaultdict(list)      # ip -> [time, ...]
users_tried = defaultdict(set) # ip -> {usernames}
successes = []                 # (time, ip, user)

with open(LOG_FILE) as f:
    for line in f:
        m = FAILED.match(line)
        if m:
            t = parse_time(m["ts"])
            fails[m["ip"]].append(t)
            users_tried[m["ip"]].add(m["user"])
            continue
        m = ACCEPTED.match(line)
        if m:
            successes.append((parse_time(m["ts"]), m["ip"], m["user"]))

alerts = []
for ip, times in fails.items():
    times.sort()
    start_i = 0
    best = 0
    first_hit = None
    for end_i, t in enumerate(times):
        while (t - times[start_i]).total_seconds() > WINDOW_SECONDS:
            start_i += 1
        count = end_i - start_i + 1
        if count > best:
            best = count
        if count >= THRESHOLD and first_hit is None:
            first_hit = t
    if first_hit:
        # kya attack ke baad is IP se login ho gaya?
        breached = any(ip == s_ip and s_t >= first_hit for s_t, s_ip, _ in successes)
        severity = "CRITICAL" if breached else "HIGH"
        alerts.append({
            "ip": ip,
            "severity": severity,
            "failed_total": len(times),
            "max_in_window": best,
            "users_tried": ", ".join(sorted(users_tried[ip])),
            "first_alert_time": first_hit.strftime("%Y-%m-%d %H:%M:%S"),
            "login_after_attack": "YES" if breached else "no",
        })

alerts.sort(key=lambda a: a["max_in_window"], reverse=True)

print("=" * 60)
print(f" BRUTE-FORCE DETECTOR  |  file: {LOG_FILE}")
print(f" Rule: {THRESHOLD}+ failed logins in {WINDOW_SECONDS}s from one IP")
print("=" * 60)
if not alerts:
    print("Koi attack nahi mila.")
for a in alerts:
    print(f"\n[{a['severity']}] Brute-force from {a['ip']}")
    print(f"   failed attempts : {a['failed_total']} (max {a['max_in_window']} in {WINDOW_SECONDS}s)")
    print(f"   usernames tried : {a['users_tried']}")
    print(f"   first alert at  : {a['first_alert_time']}")
    if a["login_after_attack"] == "YES":
        print("   !! LOGIN SUCCEEDED after the attack -> account compromise ho sakta hai")

print("\nIPs jo alert nahi bane (normal ya bahut dheere):")
alerted = {a["ip"] for a in alerts}
for ip, times in fails.items():
    if ip not in alerted:
        print(f"   {ip}: {len(times)} failed")

if alerts:
    with open("report.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(alerts[0].keys()))
        w.writeheader()
        w.writerows(alerts)
    print("\nreport.csv save ho gayi.")