# generate_logs.py
# Nakli (fake) SSH log file banata hai, sirf practice ke liye.
import random
from datetime import datetime, timedelta

random.seed(7)
start = datetime(2026, 10, 26, 9, 0, 0)
lines = []

def stamp(t):
    return t.strftime("%b %d %H:%M:%S")

def add(t, text):
    lines.append((t, f"{stamp(t)} ubuntu sshd[{random.randint(1000, 9999)}]: {text}"))

# 1) Normal users, kabhi-kabhi ek typo
normal_ips = ["192.168.56.1", "192.168.56.20", "10.0.0.15"]
users = ["bhoomi", "admin_lab", "student"]
t = start
for _ in range(25):
    t += timedelta(minutes=random.randint(3, 15))
    ip = random.choice(normal_ips)
    user = random.choice(users)
    port = random.randint(40000, 60000)
    if random.random() < 0.15:
        add(t, f"Failed password for {user} from {ip} port {port} ssh2")
    add(t + timedelta(seconds=5), f"Accepted password for {user} from {ip} port {port} ssh2")

# 2) Brute-force attack: ek IP se 1 minute mein bahut fail
attacker = "203.0.113.45"
t = start + timedelta(hours=1, minutes=10)
for i in range(18):
    t += timedelta(seconds=random.randint(1, 4))
    user = random.choice(["root", "admin", "labuser", "test"])
    port = random.randint(40000, 60000)
    if user in ("root", "admin", "test"):
        add(t, f"Failed password for invalid user {user} from {attacker} port {port} ssh2")
    else:
        add(t, f"Failed password for {user} from {attacker} port {port} ssh2")

# 3) Dusra attacker: kuch fail ke baad login ho gaya (sabse khatarnaak)
attacker2 = "198.51.100.77"
t = start + timedelta(hours=2, minutes=5)
for i in range(7):
    t += timedelta(seconds=random.randint(2, 6))
    add(t, f"Failed password for labuser from {attacker2} port {random.randint(40000, 60000)} ssh2")
t += timedelta(seconds=4)
add(t, f"Accepted password for labuser from {attacker2} port {random.randint(40000, 60000)} ssh2")

# 4) Dheere-dheere try karne wala (alert nahi hona chahiye)
slow = "192.0.2.9"
t = start + timedelta(hours=3)
for i in range(4):
    t += timedelta(minutes=random.randint(10, 20))
    add(t, f"Failed password for student from {slow} port {random.randint(40000, 60000)} ssh2")

lines.sort(key=lambda x: x[0])
with open("auth.log", "w") as f:
    for _, text in lines:
        f.write(text + "\n")
print(f"auth.log ban gayi: {len(lines)} lines")