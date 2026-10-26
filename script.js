function loadSampleLog() {
  const sample = `Oct 26 09:08:00 ubuntu sshd[1000]: Accepted password for bhoomi from 192.168.56.1 port 498 ssh2
Oct 26 09:40:00 ubuntu sshd[1007]: Accepted password for student from 10.0.0.15 port 4940 ssh2
Oct 26 10:10:12 ubuntu sshd[1035]: Failed password for invalid user root from 203.0.113.45 port 50000 ssh2
Oct 26 10:10:14 ubuntu sshd[1042]: Failed password for invalid user admin from 203.0.113.45 port 50013 ssh2
Oct 26 10:10:16 ubuntu sshd[1049]: Failed password for labuser from 203.0.113.45 port 50026 ssh2
Oct 26 10:10:18 ubuntu sshd[1056]: Failed password for invalid user root from 203.0.113.45 port 50039 ssh2
Oct 26 10:10:20 ubuntu sshd[1063]: Failed password for invalid user admin from 203.0.113.45 port 50052 ssh2
Oct 26 10:10:22 ubuntu sshd[1070]: Failed password for invalid user test from 203.0.113.45 port 50065 ssh2
Oct 26 11:05:10 ubuntu sshd[1100]: Failed password for labuser from 198.51.100.77 port 4001 ssh2
Oct 26 11:05:12 ubuntu sshd[1101]: Failed password for labuser from 198.51.100.77 port 4002 ssh2
Oct 26 11:05:14 ubuntu sshd[1102]: Failed password for labuser from 198.51.100.77 port 4003 ssh2
Oct 26 11:05:18 ubuntu sshd[1105]: Accepted password for labuser from 198.51.100.77 port 4005 ssh2
An account failed to log on. Account Name: Administrator Source Network Address: 198.51.100.99`;
  
  document.getElementById('logInput').value = sample;
}

function handleFile(files) {
  if (!files.length) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    document.getElementById('logInput').value = e.target.result;
  };
  reader.readAsText(files[0]);
}

// #9 Feature: Parses Linux SSH logs & Windows Event logs
function parseLine(line) {
  const linuxFail = line.match(/Failed password for (?:invalid user )?(\S+) from (\S+)/);
  const linuxOk = line.match(/Accepted password for (\S+) from (\S+)/);
  
  // Windows Event Logs (Event ID 4625 / 4624)
  const winFail = line.match(/Account Name:\s*(\S+).*Source Network Address:\s*(\S+)/i);

  if (linuxFail) return { type: 'fail', user: linuxFail[1], ip: linuxFail[2] };
  if (linuxOk) return { type: 'success', user: linuxOk[1], ip: linuxOk[2] };
  if (winFail) return { type: 'fail', user: winFail[1], ip: winFail[2] };
  return null;
}

function analyzeLogs() {
  const text = document.getElementById('logInput').value;
  const lines = text.split('\n');

  let totalFails = 0;
  const ipFailMap = {};
  const attackerIPs = new Set();
  let criticalCount = 0;

  lines.forEach(line => {
    const parsed = parseLine(line);
    if (parsed) {
      if (parsed.type === 'fail') {
        totalFails++;
        ipFailMap[parsed.ip] = (ipFailMap[parsed.ip] || 0) + 1;
        if (ipFailMap[parsed.ip] >= 3) {
          attackerIPs.add(parsed.ip);
        }
      } else if (parsed.type === 'success') {
        if (ipFailMap[parsed.ip] && ipFailMap[parsed.ip] >= 2) {
          criticalCount++;
        }
      }
    }
  });

  // Update Top Counter Cards
  document.getElementById('totalFails').innerText = totalFails;
  document.getElementById('totalAttackingIPs').innerText = attackerIPs.size;
  document.getElementById('totalCritical').innerText = criticalCount;

  // Render Features #3, #1 & #2
  renderBarChart(ipFailMap);
  renderTips(criticalCount, Array.from(attackerIPs));
}

// Render Visual Bar Chart (#3)
function renderBarChart(ipFailMap) {
  const chartPanel = document.getElementById('chartPanel');
  const barsContainer = document.getElementById('bars');
  barsContainer.innerHTML = '';

  const sortedIPs = Object.keys(ipFailMap).sort((a,b) => ipFailMap[b] - ipFailMap[a]);

  if (sortedIPs.length === 0) {
    chartPanel.style.display = 'none';
    return;
  }

  chartPanel.style.display = 'block';
  const maxVal = ipFailMap[sortedIPs[0]] || 1;

  sortedIPs.forEach(ip => {
    const count = ipFailMap[ip];
    const pct = Math.min((count / maxVal) * 100, 100);
    const isCritical = count >= 3;

    barsContainer.innerHTML += `
      <div class="bar-row">
        <div class="bar-label">${ip}</div>
        <div class="bar-track">
          <div class="bar-fill ${isCritical ? 'critical' : ''}" style="width: ${pct}%"></div>
        </div>
        <div class="bar-val">${count}</div>
      </div>
    `;
  });
}

// Render Block Commands & Mitigation Steps (#1 & #2)
function renderTips(criticalCount, attackerIPs) {
  const tipsPanel = document.getElementById('tipsPanel');
  const tipList = document.getElementById('tiplist');
  
  tipsPanel.style.display = 'block';
  tipList.innerHTML = '';

  if (criticalCount > 0) {
    tipList.innerHTML += `<li class="urgent">🚨 <strong>CRITICAL ALERT:</strong> Brute-force attack ke baad Login Success hua hai! Passwords reset karein aur SSH Key Auth force karein.</li>`;
  }

  attackerIPs.forEach(ip => {
    tipList.innerHTML += `<li>🛡️ <strong>Block Attacker IP (#1):</strong> Server terminal me command chalayein: <code>sudo ufw deny from ${ip}</code></li>`;
  });

  tipList.innerHTML += `
    <li>🔑 Disable root login in SSH config (Set <code>PermitRootLogin no</code> in <code>/etc/ssh/sshd_config</code>).</li>
    <li>⚡ Automatic blocking ke liye <code>fail2ban</code> tool install karein.</li>
    <li>🔒 SSH default port 22 ko change karke custom port set karein.</li>
  `;
}