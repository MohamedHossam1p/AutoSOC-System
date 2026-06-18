// ==================== ALERT HISTORY ====================
function initSearchDefaults() {
    if (!document.getElementById('es-date-from').value) {
        const t = new Date(), m = new Date();
        m.setMonth(m.getMonth() - 1);
        document.getElementById('es-date-to').value   = t.toISOString().split('T')[0];
        document.getElementById('es-date-from').value = m.toISOString().split('T')[0];
    }
}

async function runElasticSearch() {
    const ip  = document.getElementById('es-search-ip').value.trim();
    const kw  = document.getElementById('es-search-rule').value.trim();
    const fd  = document.getElementById('es-date-from').value;
    const td  = document.getElementById('es-date-to').value;
    const lvl = document.getElementById('es-severity').value;
    const se  = document.getElementById('es-status');
    se.innerText = '⏳ Searching...'; se.style.color = 'var(--accent-blue)';

    const must = [];
    if (ip)  must.push({ match: { "data.srcip": ip } });
    if (kw)  must.push({ match: { "rule.description": kw } });
    if (lvl) must.push({ range: { "rule.level": { gte: parseInt(lvl) } } });
    if (fd || td) {
        const r = { "@timestamp": {} };
        if (fd) r["@timestamp"]["gte"] = fd + "T00:00:00";
        if (td) r["@timestamp"]["lte"] = td + "T23:59:59";
        must.push({ range: r });
    }

    try {
        const res = await fetch(`${PROXY_URL}/${WAZUH_INDEX}/_search`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ size: 200, sort: [{ "@timestamp": { order: "desc" } }], query: must.length > 0 ? { bool: { must } } : { match_all: {} }, _source: ["@timestamp", "data.srcip", "agent.name", "rule.id", "rule.level", "rule.description", "rule.mitre.tactic", "rule.mitre.id"] })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        renderSearchResults(await res.json());
    } catch (err) { se.innerText = '❌ Error: ' + err.message; se.style.color = 'var(--accent-red)'; }
}

function renderSearchResults(esR) {
    const se = document.getElementById('es-status'), hits = esR.hits?.hits || [], total = esR.hits?.total?.value || 0;
    if (!hits.length) {
        se.innerText = '⚠️ No results.'; se.style.color = 'var(--accent-orange)';
        document.getElementById('es-results-body').innerHTML = '<tr><td colspan="8" class="empty-state">No alerts found.</td></tr>';
        ['es-stat-total', 'es-stat-critical', 'es-stat-ips', 'es-stat-range'].forEach(id => document.getElementById(id).innerText = '0');
        return;
    }
    se.innerText = `✅ Found ${total} alerts (showing ${hits.length})`; se.style.color = 'var(--accent-green)';
    const crit = hits.filter(h => (h._source?.rule?.level || 0) >= 15).length;
    const uIPs = new Set(hits.map(h => h._source?.data?.srcip).filter(Boolean)).size;
    const ts   = hits.map(h => h._source?.['@timestamp']).filter(Boolean).sort();
    const dr   = ts.length > 0 ? `${ts[0].split('T')[0]} → ${ts[ts.length - 1].split('T')[0]}` : '—';
    document.getElementById('es-stat-total').innerText   = total > 200 ? `${total} (200 shown)` : total;
    document.getElementById('es-stat-critical').innerText = crit;
    document.getElementById('es-stat-ips').innerText     = uIPs;
    document.getElementById('es-stat-range').innerText   = dr;

    document.getElementById('es-results-body').innerHTML = hits.map(h => {
        const src = h._source || {};
        const t   = src['@timestamp'] ? new Date(src['@timestamp']).toLocaleString('en-US', { timeZone: 'Africa/Cairo' }) : '—';
        const ip  = src.data?.srcip || '—', ag = src.agent?.name || '—', ri = src.rule?.id || '—', lv = src.rule?.level || '—', ds = src.rule?.description || '—';
        const ta  = Array.isArray(src.rule?.mitre?.tactic) ? src.rule.mitre.tactic.join(', ') : (src.rule?.mitre?.tactic || '—');
        const lc  = lv >= 15 ? 'var(--accent-red)' : lv >= 10 ? 'var(--accent-orange)' : 'var(--accent-blue)';
        return `<tr>
            <td style="font-size:12px;color:#8b949e;font-family:'IBM Plex Mono',monospace;">${t}</td>
            <td>${ip !== '—' ? `<a href="https://www.virustotal.com/gui/ip-address/${ip}/detection" target="_blank" class="ip-link" style="color:var(--accent-red);">${ip}</a>` : '—'}</td>
            <td style="color:var(--accent-blue);">${ag}</td>
            <td style="font-family:'IBM Plex Mono',monospace;color:var(--accent-purple);">${ri}</td>
            <td><span style="color:${lc};font-weight:700;">Level ${lv}</span></td>
            <td style="font-size:13px;max-width:300px;white-space:normal;">${ds}</td>
            <td style="font-size:12px;color:#8b949e;">${ta}</td>
            <td><button class="btn btn-sm" onclick="openCaseFromAlert('${ip}',${lv * 6})">+ Case</button></td>
        </tr>`;
    }).join('');
}

function resetSearchForm() {
    ['es-search-ip', 'es-search-rule', 'es-date-from', 'es-date-to'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('es-severity').value = '';
    document.getElementById('es-status').innerText = '';
    document.getElementById('es-results-body').innerHTML = '<tr><td colspan="8" class="empty-state">Use the search form above.</td></tr>';
    ['es-stat-total', 'es-stat-critical', 'es-stat-ips', 'es-stat-range'].forEach(id => document.getElementById(id).innerText = '—');
}