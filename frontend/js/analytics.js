// ==================== ANALYTICS ====================
function buildAnalyticsCharts() {
    const d = window._analyticsData;
    if (!d) return;
    drawBarChart('chart-countries', d.countryFreq, '#58a6ff');
    drawBarChart('chart-isps', d.ispFreq, '#bc8cff');
    drawBarChart('chart-risk', d.riskBuckets, '#ff4444', true);
    drawTorDonut(d.torHits, d.totalCount - d.torHits);
    drawTimelineChart(d.dailyHits);
}

function drawBarChart(id, dataMap, color, keepOrder = false) {
    let entries = Object.entries(dataMap);
    if (!keepOrder) entries.sort((a, b) => b[1] - a[1]);
    entries = entries.slice(0, 8);
    const max = Math.max(...entries.map(e => e[1]), 1);
    document.getElementById(id).innerHTML = entries.map(([label, count]) =>
        `<div class="bar-item">
            <div class="bar-label" title="${label}">${label}</div>
            <div class="bar-track"><div class="bar-fill" style="width:${(count / max * 100).toFixed(1)}%;background:${color};">${count}</div></div>
            <div class="bar-count">${count}</div>
        </div>`).join('');
}

function drawTorDonut(tor, nonTor) {
    const canvas = document.getElementById('torCanvas'), ctx = canvas.getContext('2d');
    const total = tor + nonTor || 1, torArc = (tor / total) * Math.PI * 2, cx = 80, cy = 80, r = 60, t = 20;
    ctx.clearRect(0, 0, 160, 160);
    ctx.beginPath(); ctx.arc(cx, cy, r, 0, Math.PI * 2); ctx.lineWidth = t; ctx.strokeStyle = '#58a6ff'; ctx.stroke();
    if (tor > 0) { ctx.beginPath(); ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + torArc); ctx.lineWidth = t; ctx.strokeStyle = '#f2a60c'; ctx.stroke(); }
    ctx.fillStyle = '#fff'; ctx.font = 'bold 22px IBM Plex Mono'; ctx.textAlign = 'center'; ctx.fillText(total, cx, cy + 4);
    ctx.font = '11px IBM Plex Sans'; ctx.fillStyle = '#8b949e'; ctx.fillText('TOTAL', cx, cy + 18);
    document.getElementById('tor-legend').innerHTML =
        `<div class="legend-item"><div class="legend-dot" style="background:#58a6ff;"></div>Non-TOR: ${nonTor}</div>
         <div class="legend-item"><div class="legend-dot" style="background:#f2a60c;"></div>TOR: ${tor}</div>`;
}

function drawTimelineChart(dailyHitsMap) {
    const canvas = document.getElementById('timelineCanvas'), ctx = canvas.getContext('2d');
    const w = canvas.parentElement.offsetWidth - 40;
    canvas.width = w;
    const today = new Date(), days = [];
    for (let i = 13; i >= 0; i--) { const d = new Date(today); d.setDate(d.getDate() - i); days.push(d.toISOString().split('T')[0]); }
    const values = days.map(d => dailyHitsMap[d] || 0), max = Math.max(...values, 1), h = canvas.height, barW = w / days.length - 4;
    ctx.clearRect(0, 0, w, h);
    days.forEach((day, i) => {
        const val = values[i], barH = (val / max) * (h - 30), x = i * (w / days.length) + 2, y = h - barH - 20;
        const grad = ctx.createLinearGradient(0, y, 0, h);
        grad.addColorStop(0, '#58a6ff'); grad.addColorStop(1, 'rgba(88,166,255,0.2)');
        ctx.fillStyle = grad; ctx.beginPath(); ctx.roundRect(x, y, barW, barH, 3); ctx.fill();
        ctx.fillStyle = '#8b949e'; ctx.font = '10px IBM Plex Sans'; ctx.textAlign = 'center'; ctx.fillText(day.slice(5), x + barW / 2, h - 4);
        if (val > 0) { ctx.fillStyle = '#fff'; ctx.font = 'bold 11px IBM Plex Sans'; ctx.fillText(val, x + barW / 2, y - 4); }
    });
}