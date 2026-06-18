// ==================== THREAT HUNTING ====================
const huntDefs = {
    top_attackers: {
        label: "Top Attacking IPs", type: "aggregation",
        q: (d) => ({ size: 0, query: { bool: { must: [{ exists: { field: "data.srcip" } }, { range: { "@timestamp": { gte: `now-${d}d/d` } } }] } }, aggs: { top_ips: { terms: { field: "data.srcip", size: 20 }, aggs: { top_rules: { terms: { field: "rule.description", size: 3 } } } } } })
    },
    brute_force: {
        label: "Brute Force Detection", type: "aggregation",
        q: (d) => ({ size: 0, query: { bool: { must: [{ exists: { field: "data.srcip" } }, { match: { "rule.groups": "authentication_failed" } }, { range: { "@timestamp": { gte: `now-${d}d/d` } } }] } }, aggs: { attackers: { terms: { field: "data.srcip", size: 20, min_doc_count: 5 } } } })
    },
    off_hours: {
        label: "Off-Hours Activity", type: "hits",
        q: (d) => ({ size: 100, sort: [{ "@timestamp": { order: "desc" } }], query: { bool: { must: [{ range: { "@timestamp": { gte: `now-${d}d/d` } } }, { script: { script: { source: "def utcH=doc['@timestamp'].value.getHour();def cairoH=(utcH+2)%24;return cairoH>=0&&cairoH<=6;", lang: "painless" } } }] } }, _source: ["@timestamp", "data.srcip", "agent.name", "rule.id", "rule.level", "rule.description", "rule.mitre.tactic"] })
    },
    priv_esc: {
        label: "Privilege Escalation", type: "hits",
        q: (d) => ({ size: 100, sort: [{ "@timestamp": { order: "desc" } }], query: { bool: { must: [{ range: { "@timestamp": { gte: `now-${d}d/d` } } }, { bool: { should: [{ match: { "rule.description": "sudo" } }, { match: { "rule.description": "privilege" } }, { terms: { "rule.id": ["100110", "100111", "100112"] } }] } }] } }, _source: ["@timestamp", "data.srcip", "data.srcuser", "agent.name", "rule.id", "rule.level", "rule.description", "rule.mitre.tactic"] })
    },
    critical_rules: {
        label: "Critical Rule Triggers", type: "hits",
        q: (d) => ({ size: 200, sort: [{ "@timestamp": { order: "desc" } }], query: { bool: { must: [{ range: { "@timestamp": { gte: `now-${d}d/d` } } }, { range: { "rule.level": { gte: 15 } } }] } }, _source: ["@timestamp", "data.srcip", "agent.name", "rule.id", "rule.level", "rule.description", "rule.mitre.tactic"] })
    },
    new_agents: {
        label: "Multi-Agent Attackers", type: "aggregation_multi_agent",
        q: (d) => ({ size: 0, query: { bool: { must: [{ exists: { field: "data.srcip" } }, { range: { "@timestamp": { gte: `now-${d}d/d` } } }] } }, aggs: { attackers: { terms: { field: "data.srcip", size: 20 }, aggs: { agents: { cardinality: { field: "agent.name" } } } } } })
    },
    file_integrity: {
        label: "File Integrity Violations", type: "hits",
        q: (d) => ({ size: 100, sort: [{ "@timestamp": { order: "desc" } }], query: { bool: { must: [{ range: { "@timestamp": { gte: `now-${d}d/d` } } }, { bool: { should: [{ match: { "rule.groups": "syscheck" } }, { terms: { "rule.id": ["550", "553", "554", "100113"] } }] } }] } }, _source: ["@timestamp", "data.srcip", "agent.name", "rule.id", "rule.level", "rule.description", "syscheck.path", "rule.mitre.tactic"] })
    },
};

async function runHuntQuery(name, event) {
    const se = document.getElementById('hunt-status'), sr = document.getElementById('hunt-stats-row'), rc = document.getElementById('hunt-results-container');
    document.querySelectorAll('.hunt-card').forEach(c => c.classList.remove('running'));
    if (event?.currentTarget) event.currentTarget.classList.add('running');
    se.style.display = 'block'; sr.style.display = 'none'; rc.style.display = 'none';

    const dd = 7;
    let qBody, ql, qt;

    if (name === 'custom') {
        const kw = document.getElementById('hunt-custom-keyword').value.trim();
        const ip = document.getElementById('hunt-custom-ip').value.trim();
        const lv = document.getElementById('hunt-custom-level').value;
        const dy = document.getElementById('hunt-custom-days').value;
        ql = 'Custom Hunt'; qt = 'hits';
        const mu = [{ range: { "@timestamp": { gte: `now-${dy}d/d` } } }];
        if (kw) mu.push({ match: { "rule.description": kw } });
        if (ip) mu.push({ match: { "data.srcip": ip } });
        if (lv) mu.push({ range: { "rule.level": { gte: parseInt(lv) } } });
        qBody = { size: 200, sort: [{ "@timestamp": { order: "desc" } }], query: { bool: { must: mu } }, _source: ["@timestamp", "data.srcip", "agent.name", "rule.id", "rule.level", "rule.description", "rule.mitre.tactic"] };
        se.innerText = '⏳ Running custom hunt...'; se.style.color = 'var(--accent-blue)';
    } else {
        const def = huntDefs[name]; ql = def.label; qt = def.type; qBody = def.q(dd);
        se.innerText = `⏳ Hunting: ${ql}...`; se.style.color = 'var(--accent-blue)';
    }
    await execHunt(qBody, qt, ql);
    document.querySelectorAll('.hunt-card').forEach(c => c.classList.remove('running'));
}

async function execHunt(qBody, rType, ql) {
    const se = document.getElementById('hunt-status'), sr = document.getElementById('hunt-stats-row');
    const rc = document.getElementById('hunt-results-container'), tb = document.getElementById('hunt-results-body');
    try {
        const res = await fetch(`${PROXY_URL}/${WAZUH_INDEX}/_search`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(qBody) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();

        if (rType === 'aggregation') {
            const bk = data.aggregations?.top_ips?.buckets || data.aggregations?.attackers?.buckets || [];
            if (!bk.length) { se.innerText = `⚠️ No results for: ${ql}`; se.style.color = 'var(--accent-orange)'; return; }
            se.innerText = `✅ ${ql} — Found ${bk.length} unique IPs`; se.style.color = 'var(--accent-green)';
            document.getElementById('hunt-stat-total').innerText    = bk.length;
            document.getElementById('hunt-stat-critical').innerText = bk.filter(b => b.doc_count >= 50).length;
            document.getElementById('hunt-stat-ips').innerText      = bk.length;
            document.getElementById('hunt-stat-agents').innerText   = '—';
            sr.style.display = 'grid'; sr.style.gridTemplateColumns = 'repeat(4,1fr)';
            tb.innerHTML = bk.map(b => {
                const vt = `https://www.virustotal.com/gui/ip-address/${b.key}/detection`;
                const cc = b.doc_count >= 100 ? 'var(--accent-red)' : b.doc_count >= 20 ? 'var(--accent-orange)' : 'var(--accent-blue)';
                const tr = b.top_rules?.buckets?.map(r => r.key).join(' | ') || '—';
                return `<tr>
                    <td style="color:#8b949e;font-size:12px;">—</td>
                    <td><a href="${vt}" target="_blank" class="ip-link" style="color:var(--accent-red);">${b.key}</a></td>
                    <td style="color:#8b949e;">—</td>
                    <td style="color:var(--accent-purple);">—</td>
                    <td><span style="color:${cc};font-weight:700;">${b.doc_count} hits</span></td>
                    <td style="font-size:13px;max-width:300px;white-space:normal;">${tr}</td>
                    <td>—</td>
                    <td><button class="btn btn-sm" onclick="openCaseFromAlert('${b.key}',${Math.min(b.doc_count * 2, 100)})">+ Case</button></td>
                </tr>`;
            }).join('');
            rc.style.display = 'block'; return;
        }

        if (rType === 'aggregation_multi_agent') {
            const bk = (data.aggregations?.attackers?.buckets || []).filter(b => b.agents?.value > 1);
            if (!bk.length) { se.innerText = '✅ No multi-agent attackers!'; se.style.color = 'var(--accent-green)'; return; }
            se.innerText = `🚨 ${ql} — ${bk.length} IPs attacking multiple agents!`; se.style.color = 'var(--accent-red)';
            document.getElementById('hunt-stat-total').innerText    = bk.length;
            document.getElementById('hunt-stat-critical').innerText = bk.filter(b => b.agents?.value >= 3).length;
            document.getElementById('hunt-stat-ips').innerText      = bk.length;
            document.getElementById('hunt-stat-agents').innerText   = Math.max(...bk.map(b => b.agents?.value || 0));
            sr.style.display = 'grid'; sr.style.gridTemplateColumns = 'repeat(4,1fr)';
            tb.innerHTML = bk.map(b => {
                const vt = `https://www.virustotal.com/gui/ip-address/${b.key}/detection`;
                const ac = b.agents?.value || 0, aclr = ac >= 3 ? 'var(--accent-red)' : 'var(--accent-orange)';
                return `<tr>
                    <td style="color:#8b949e;font-size:12px;">—</td>
                    <td><a href="${vt}" target="_blank" class="ip-link" style="color:var(--accent-red);">${b.key}</a></td>
                    <td><span style="color:${aclr};font-weight:700;">${ac} agents</span></td>
                    <td style="color:var(--accent-purple);">—</td>
                    <td><span style="color:var(--accent-orange);font-weight:700;">${b.doc_count} hits</span></td>
                    <td>Attacked ${ac} agents</td>
                    <td style="color:var(--accent-orange);">Lateral Movement</td>
                    <td><button class="btn btn-sm" onclick="openCaseFromAlert('${b.key}',85)">+ Case</button></td>
                </tr>`;
            }).join('');
            rc.style.display = 'block'; return;
        }

        const hits  = data.hits?.hits || [], total = data.hits?.total?.value || 0;
        if (!hits.length) { se.innerText = `✅ No suspicious activity for: ${ql}`; se.style.color = 'var(--accent-green)'; return; }
        se.innerText = `🎯 ${ql} — Found ${total} events (showing ${hits.length})`; se.style.color = 'var(--accent-red)';
        const crit   = hits.filter(h => (h._source?.rule?.level || 0) >= 15).length;
        const uIPs   = new Set(hits.map(h => h._source?.data?.srcip).filter(Boolean)).size;
        const uAg    = new Set(hits.map(h => h._source?.agent?.name).filter(Boolean)).size;
        document.getElementById('hunt-stat-total').innerText    = total > 200 ? `${total}` : total;
        document.getElementById('hunt-stat-critical').innerText = crit;
        document.getElementById('hunt-stat-ips').innerText      = uIPs;
        document.getElementById('hunt-stat-agents').innerText   = uAg;
        sr.style.display = 'grid'; sr.style.gridTemplateColumns = 'repeat(4,1fr)';
        tb.innerHTML = hits.map(h => {
            const src = h._source || {};
            const ts  = src['@timestamp'] ? new Date(src['@timestamp']).toLocaleString('en-US', { timeZone: 'Africa/Cairo' }) : '—';
            const ip  = src.data?.srcip || '—', ag = src.agent?.name || '—', ri = src.rule?.id || '—', lv = src.rule?.level || '—', ds = src.rule?.description || '—';
            const ta  = Array.isArray(src.rule?.mitre?.tactic) ? src.rule.mitre.tactic[0] : (src.rule?.mitre?.tactic || '—');
            const lc  = lv >= 15 ? 'var(--accent-red)' : lv >= 10 ? 'var(--accent-orange)' : 'var(--accent-blue)';
            return `<tr>
                <td style="font-size:12px;color:#8b949e;font-family:'IBM Plex Mono',monospace;">${ts}</td>
                <td>${ip !== '—' ? `<a href="https://www.virustotal.com/gui/ip-address/${ip}/detection" target="_blank" class="ip-link" style="color:var(--accent-red);">${ip}</a>` : '—'}</td>
                <td style="color:var(--accent-blue);">${ag}</td>
                <td style="font-family:'IBM Plex Mono',monospace;color:var(--accent-purple);">${ri}</td>
                <td><span style="color:${lc};font-weight:700;">Level ${lv}</span></td>
                <td style="font-size:13px;max-width:280px;white-space:normal;">${ds}</td>
                <td style="font-size:12px;color:#8b949e;">${ta}</td>
                <td><button class="btn btn-sm" onclick="openCaseFromAlert('${ip}',${lv >= 15 ? 90 : lv >= 10 ? 70 : 40})">+ Case</button></td>
            </tr>`;
        }).join('');
        rc.style.display = 'block';
    } catch (err) { se.innerText = `❌ Hunt failed: ${err.message}`; se.style.color = 'var(--accent-red)'; }
}