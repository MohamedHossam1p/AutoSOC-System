// ==================== LIVE ALERTS ====================
async function fetchLiveAlerts() {
    try {
        const res = await fetch(`${LIVE_URL}/${LIVE_INDEX}/_search`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ size: 500, sort: [{ "@timestamp": { order: "desc" } }], query: { match_all: {} } })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const payload = await res.json();
        alertRows = (payload.hits?.hits || []).map(h => {
            const s = h._source;
            return [
                s.attacker_ip || '', s.country || '', String(s.risk_score || 0),
                s.isp || '', s.is_tor ? 'TRUE' : 'FALSE', String(s.reports || 0),
                s['@timestamp'] || '', String(s.lat || ''), String(s.lon || '')
            ];
        });
        buildAlertsTable(alertRows);
        document.getElementById('connection-status-text').innerText = "Live Monitoring Sync Active";
        document.querySelector('.status-dot').style.backgroundColor = "var(--accent-green)";
        document.querySelector('.status-dot').style.boxShadow = "0 0 10px var(--accent-green)";
    } catch (err) {
        document.getElementById('connection-status-text').innerText = "Connection Error - Retrying...";
        document.querySelector('.status-dot').style.backgroundColor = "var(--accent-red)";
    }
}

function getRiskColor(s) {
    if (s >= 76) return '#ff4444';
    if (s >= 51) return '#f2a60c';
    if (s >= 26) return '#58a6ff';
    return '#2ea043';
}

function getRiskLabel(s) {
    if (s >= 76) return 'Critical';
    if (s >= 51) return 'High';
    if (s >= 26) return 'Medium';
    return 'Low';
}

function fmtTime(ts) {
    try {
        return new Date(ts).toLocaleString('en-US', {
            timeZone: 'Africa/Cairo', year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true
        });
    } catch (e) { return ts; }
}

function buildAlertsTable(rows) {
    let totalCount = 0, criticalHits = 0, torHits = 0;
    let countryFreq = {}, ispFreq = {}, riskBuckets = { '0-25': 0, '26-50': 0, '51-75': 0, '76-100': 0 }, dailyHits = {};
    const ipMap = {};
    attackerMarkers.clearLayers();

    rows.forEach(row => {
        if (row.length < 2 || !row[0]) return;
        totalCount++;
        const ip = row[0], country = (row[1] || '').split('(')[0].trim(), riskScore = parseInt(row[2]) || 0;
        const isp = row[3] || '', isTor = row[4] === 'TRUE', lat = parseFloat(row[7]), lng = parseFloat(row[8]), ts = row[6] || '';

        if (country) countryFreq[country] = (countryFreq[country] || 0) + 1;
        if (isp) ispFreq[isp] = (ispFreq[isp] || 0) + 1;

        if (riskScore >= 76) { criticalHits++; riskBuckets['76-100']++; }
        else if (riskScore >= 51) riskBuckets['51-75']++;
        else if (riskScore >= 26) riskBuckets['26-50']++;
        else riskBuckets['0-25']++;

        if (isTor) torHits++;

        try { const dk = new Date(ts).toISOString().split('T')[0]; dailyHits[dk] = (dailyHits[dk] || 0) + 1; } catch (e) {}

        if (!isNaN(lat) && !isNaN(lng)) {
            const dot = L.circleMarker([lat, lng], {
                radius: riskScore >= 76 ? 9 : 7,
                fillColor: riskScore >= 76 ? '#ff4444' : riskScore >= 51 ? '#f2a60c' : riskScore >= 26 ? '#58a6ff' : '#2ea043',
                color: '#fff', weight: 1, fillOpacity: 0.85
            });
            dot.bindPopup(`<b>${ip}</b><br>${row[1]}<br>Risk: ${riskScore} (${getRiskLabel(riskScore)})`);
            attackerMarkers.addLayer(dot);
        }

        if (!ipMap[ip]) {
            ipMap[ip] = { ip, country: row[1] || '', isp, maxRisk: riskScore, isTor, lastSeen: ts, alertCount: 1, allAlerts: [row] };
        } else {
            const g = ipMap[ip];
            g.alertCount++;
            g.allAlerts.push(row);
            if (riskScore > g.maxRisk) g.maxRisk = riskScore;
            if (isTor) g.isTor = true;
            if (ts > g.lastSeen) g.lastSeen = ts;
        }
    });

    groupedAlerts = Object.values(ipMap);
    updateSummaryCards(totalCount, criticalHits, torHits, countryFreq);
    bindSearchFilter();
    window._analyticsData = { countryFreq, ispFreq, riskBuckets, dailyHits, torHits, totalCount };
    renderSortedTable();
}

function applySort(mode, btnEl) {
    currentSort = mode;
    document.querySelectorAll('.sort-btn').forEach(b => b.classList.remove('active', 'active-red', 'active-orange', 'active-green'));
    if (btnEl) {
        if (mode === 'time' || mode === 'risk_desc' || mode === 'risk_asc') btnEl.classList.add('active');
        else if (mode === 'case_open') btnEl.classList.add('active-red');
        else if (mode === 'case_investigating') btnEl.classList.add('active-orange');
        else if (mode === 'case_closed') btnEl.classList.add('active-green');
    }
    renderSortedTable();
}

function renderSortedTable() {
    if (!groupedAlerts.length) return;
    const openIPs          = new Set(caseList.filter(c => c.status === 'Open').map(c => c.ip));
    const investigatingIPs = new Set(caseList.filter(c => c.status === 'Investigating').map(c => c.ip));
    const closedIPs        = new Set(caseList.filter(c => c.status === 'Closed').map(c => c.ip));
    const sorted = [...groupedAlerts];

    if (currentSort === 'time')               sorted.sort((a, b) => b.lastSeen > a.lastSeen ? 1 : -1);
    else if (currentSort === 'risk_desc')     sorted.sort((a, b) => b.maxRisk - a.maxRisk);
    else if (currentSort === 'risk_asc')      sorted.sort((a, b) => a.maxRisk - b.maxRisk);
    else if (currentSort === 'case_open')     sorted.sort((a, b) => (openIPs.has(b.ip) ? 1 : 0) - (openIPs.has(a.ip) ? 1 : 0));
    else if (currentSort === 'case_investigating') sorted.sort((a, b) => (investigatingIPs.has(b.ip) ? 1 : 0) - (investigatingIPs.has(a.ip) ? 1 : 0));
    else if (currentSort === 'case_closed')   sorted.sort((a, b) => (closedIPs.has(b.ip) ? 1 : 0) - (closedIPs.has(a.ip) ? 1 : 0));

    const tbody = document.getElementById('logs-body');
    tbody.innerHTML = '';
    if (!sorted.length) { tbody.innerHTML = '<tr><td colspan="9" class="empty-state">No live alerts yet.</td></tr>'; return; }

    sorted.forEach(g => {
        const rc = getRiskColor(g.maxRisk), rl = getRiskLabel(g.maxRisk), hasMany = g.alertCount > 1;
        let badgeHtml = '';
        if (openIPs.has(g.ip))          badgeHtml = `<span style="margin-left:6px;font-size:10px;padding:2px 7px;border-radius:8px;background:rgba(255,68,68,0.15);color:#ff4444;border:1px solid #ff4444;font-weight:700;">OPEN</span>`;
        else if (investigatingIPs.has(g.ip)) badgeHtml = `<span style="margin-left:6px;font-size:10px;padding:2px 7px;border-radius:8px;background:rgba(242,166,12,0.15);color:#f2a60c;border:1px solid #f2a60c;font-weight:700;">INVEST.</span>`;
        else if (closedIPs.has(g.ip))   badgeHtml = `<span style="margin-left:6px;font-size:10px;padding:2px 7px;border-radius:8px;background:rgba(46,160,67,0.15);color:#2ea043;border:1px solid #2ea043;font-weight:700;">CLOSED</span>`;

        const summaryRow = document.createElement('tr');
        summaryRow.style.borderLeft = `3px solid ${rc}`;
        summaryRow.innerHTML = `
            <td style="text-align:center;padding:10px 6px;">${hasMany ? `<button data-ip="${g.ip}" style="background:none;border:1px solid var(--border-color);color:#8b949e;border-radius:4px;padding:2px 8px;cursor:pointer;font-size:12px;">▶</button>` : ''}</td>
            <td><a href="https://www.virustotal.com/gui/ip-address/${g.ip}/detection" target="_blank" class="ip-link" style="color:var(--accent-red);font-family:'IBM Plex Mono',monospace;">${g.ip}</a>${badgeHtml}</td>
            <td style="color:#8b949e;">${g.country}</td>
            <td><span style="display:inline-flex;align-items:center;gap:6px;">
                <span style="width:8px;height:8px;border-radius:50%;background:${rc};box-shadow:0 0 5px ${rc};flex-shrink:0;"></span>
                <span style="color:${rc};font-weight:700;font-family:'IBM Plex Mono',monospace;">${g.maxRisk}</span>
                <span style="font-size:11px;color:#8b949e;">${rl}</span>
            </span></td>
            <td style="color:#8b949e;font-size:13px;">${g.isp}</td>
            <td style="color:${g.isTor ? 'var(--accent-orange)' : '#8b949e'};font-weight:${g.isTor ? '700' : '400'};">${g.isTor ? '🧅 TRUE' : 'FALSE'}</td>
            <td><span style="font-family:'IBM Plex Mono',monospace;color:var(--accent-blue);font-weight:700;">${g.alertCount}</span> <span style="font-size:11px;color:#8b949e;">hit${g.alertCount !== 1 ? 's' : ''}</span></td>
            <td style="font-size:12px;color:#8b949e;">${fmtTime(g.lastSeen)}</td>
            <td><button class="btn btn-sm" onclick="openCaseFromAlert('${g.ip}',${g.maxRisk})">+ Case</button></td>`;
        tbody.appendChild(summaryRow);

        if (hasMany) {
            const btn = summaryRow.querySelector('button[data-ip]');
            const detailRow = document.createElement('tr');
            detailRow.style.display = 'none';
            const subAlerts = [...g.allAlerts].sort((a, b) => b[6] > a[6] ? 1 : -1);
            detailRow.innerHTML = `<td colspan="9" style="padding:0;background:rgba(88,166,255,0.03);border-left:3px solid ${rc};">
                <table style="width:100%;border-collapse:collapse;">
                    <thead><tr style="background:#161d2b;">
                        <th style="padding:7px 14px 7px 44px;color:var(--accent-blue);font-size:10px;text-transform:uppercase;letter-spacing:1px;text-align:left;width:220px;">Timestamp</th>
                        <th style="padding:7px 14px;color:var(--accent-blue);font-size:10px;text-transform:uppercase;text-align:left;">Risk</th>
                        <th style="padding:7px 14px;color:var(--accent-blue);font-size:10px;text-transform:uppercase;text-align:left;">Reports</th>
                        <th style="padding:7px 14px;color:var(--accent-blue);font-size:10px;text-transform:uppercase;text-align:left;">TOR</th>
                    </tr></thead>
                    <tbody>${subAlerts.map(row => {
                        const sc = parseInt(row[2]) || 0, rc2 = getRiskColor(sc), iT = row[4] === 'TRUE';
                        return `<tr style="border-bottom:1px solid var(--border-color);">
                            <td style="padding:7px 14px 7px 44px;color:#8b949e;font-family:'IBM Plex Mono',monospace;font-size:12px;">${fmtTime(row[6])}</td>
                            <td style="padding:7px 14px;"><span style="color:${rc2};font-weight:700;font-size:12px;">${sc}</span> <span style="font-size:10px;color:#8b949e;">${getRiskLabel(sc)}</span></td>
                            <td style="padding:7px 14px;color:#8b949e;font-size:12px;">${row[5] || '0'}</td>
                            <td style="padding:7px 14px;color:${iT ? 'var(--accent-orange)' : '#8b949e'};font-size:12px;">${iT ? '🧅 TRUE' : 'FALSE'}</td>
                        </tr>`;
                    }).join('')}</tbody>
                </table></td>`;
            tbody.appendChild(detailRow);
            btn.addEventListener('click', () => {
                const isOpen = detailRow.style.display !== 'none';
                detailRow.style.display = isOpen ? 'none' : 'table-row';
                btn.textContent = isOpen ? '▶' : '▼';
                btn.style.color = isOpen ? '#8b949e' : 'var(--accent-blue)';
                btn.style.borderColor = isOpen ? 'var(--border-color)' : 'var(--accent-blue)';
            });
        }
    });
}

function updateSummaryCards(total, critical, tor, countryFreq) {
    document.getElementById('stat-total').innerText    = total;
    document.getElementById('stat-critical').innerText = critical;
    document.getElementById('stat-tor').innerText      = tor;
    let top = "N/A", mx = 0;
    for (let c in countryFreq) { if (countryFreq[c] > mx) { mx = countryFreq[c]; top = c; } }
    document.getElementById('stat-country').innerText = top !== "N/A" ? `${top} (${mx})` : "N/A";
    refreshCaseCounters();
}

function bindSearchFilter() {
    document.getElementById('search-input').oninput = function () {
        const term = this.value.toLowerCase();
        document.querySelectorAll('#logs-body tr').forEach(row =>
            row.classList.toggle('hidden', !row.innerText.toLowerCase().includes(term)));
    };
}