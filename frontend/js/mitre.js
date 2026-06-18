// ==================== MITRE ====================
async function loadMitreData(days, btn) {
    mitreDaysFilter = days;
    document.querySelectorAll('.mitre-toolbar button').forEach(b => b.classList.remove('active-range'));
    if (btn) btn.classList.add('active-range');
    document.getElementById('mitre-loading').style.display      = 'flex';
    document.getElementById('mitre-live-wrapper').style.display = 'none';
    document.getElementById('mitre-error').style.display        = 'none';

    const timeFilter = days > 0 ? { range: { "@timestamp": { gte: `now-${days}d/d` } } } : { match_all: {} };
    const esQuery = {
        size: 0,
        query: { bool: { must: [timeFilter, { exists: { field: "rule.mitre.tactic" } }] } },
        aggs: {
            tactics: { terms: { field: "rule.mitre.tactic", size: 30 }, aggs: { techniques: { terms: { field: "rule.mitre.id", size: 20 } }, technique_names: { terms: { field: "rule.mitre.technique", size: 20 } } } },
            unique_techniques: { cardinality: { field: "rule.mitre.id" } }
        }
    };

    try {
        const res = await fetch(`${PROXY_URL}/${WAZUH_INDEX}/_search`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(esQuery) });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        const tb = data.aggregations?.tactics?.buckets || [];
        const ut = data.aggregations?.unique_techniques?.value || 0;
        const total = tb.reduce((s, b) => s + b.doc_count, 0);

        document.getElementById('mitre-loading').style.display = 'none';
        if (!tb.length) { document.getElementById('mitre-error').style.display = 'block'; showMitreStaticFallback(); return; }

        document.getElementById('mitre-live-wrapper').style.display = 'flex';
        document.getElementById('ms-total-alerts').innerText = total.toLocaleString();
        document.getElementById('ms-tactics').innerText      = tb.length;
        document.getElementById('ms-techniques').innerText   = ut;
        document.getElementById('ms-top-tactic').innerText   = tb[0]?.key || '—';
        document.getElementById('mitre-last-updated').innerText = '✅ Updated: ' + new Date().toLocaleTimeString('en-US');

        tacticBucketMap = {};
        tb.forEach(b => { tacticBucketMap[b.key] = b; });

        const maxTC = tb[0]?.doc_count || 1;
        document.getElementById('mitre-tactics-list').innerHTML = tb.map(b => {
            const fp = ((b.doc_count / maxTC) * 100).toFixed(0);
            const cc = b.doc_count >= 500 ? 'tactic-count-critical' : b.doc_count >= 100 ? 'tactic-count-high' : b.doc_count > 0 ? 'tactic-count-low' : 'tactic-count-zero';
            const bc = b.doc_count >= 500 ? 'var(--accent-red)' : b.doc_count >= 100 ? 'var(--accent-orange)' : 'var(--accent-blue)';
            return `<div class="tactic-row" onclick="showTechniquesByTactic('${b.key}',this)">
                <div><div class="tactic-row-name">${b.key}</div><div class="tactic-heatbar"><div class="tactic-heatbar-fill" style="width:${fp}%;background:${bc};"></div></div></div>
                <div class="tactic-row-count ${cc}">${b.doc_count.toLocaleString()}</div>
            </div>`;
        }).join('');

        const firstRow = document.querySelector('.tactic-row');
        if (firstRow) showTechniquesByTactic(tb[0].key, firstRow);
    } catch (err) {
        document.getElementById('mitre-loading').style.display = 'none';
        document.getElementById('mitre-error').style.display   = 'block';
        showMitreStaticFallback();
    }
}

function showTechniquesByTactic(tacticName, rowEl) {
    document.querySelectorAll('.tactic-row').forEach(r => r.classList.remove('active-tactic'));
    if (rowEl) rowEl.classList.add('active-tactic');
    const bucket = tacticBucketMap[tacticName];
    if (!bucket) return;
    document.getElementById('mitre-techniques-header').innerText = `📋 ${tacticName} — Techniques (${bucket.doc_count.toLocaleString()} alerts)`;
    const techIds = bucket.techniques?.buckets || [];
    const techNames = {};
    (bucket.technique_names?.buckets || []).forEach((b, i) => { techNames[i] = b.key; });
    if (!techIds.length) { document.getElementById('mitre-techniques-grid').innerHTML = '<div style="color:#8b949e;font-size:13px;padding:20px;">No technique data.</div>'; return; }
    const maxTech = techIds[0]?.doc_count || 1;
    document.getElementById('mitre-techniques-grid').innerHTML = techIds.map((t, i) => {
        const fp = Math.round((t.doc_count / maxTech) * 100), hasAlerts = t.doc_count > 0, techName = techNames[i] || '—';
        const click = hasAlerts ? `onclick="drillIntoTechnique('${t.key}','${techName.replace(/'/g, "\\'")}',${t.doc_count})" style="cursor:pointer;"` : '';
        return `<div class="technique-card ${hasAlerts ? 'has-alerts' : ''}" ${click} ${hasAlerts ? `title="Click to see ${t.doc_count} logs"` : ''}>
            <div class="technique-card-id">${t.key}</div>
            <div class="technique-card-name">${techName}</div>
            <div class="technique-card-count ${hasAlerts ? 'has-val' : 'no-val'}">${t.doc_count.toLocaleString()}</div>
            ${hasAlerts ? `<div style="margin-top:4px;font-size:10px;color:#8b949e;">🔍 Click to view logs</div>` : ''}
            <div style="margin-top:6px;height:3px;background:var(--bg-color);border-radius:2px;overflow:hidden;"><div style="width:${fp}%;height:100%;background:${hasAlerts ? 'var(--accent-red)' : 'var(--border-color)'};border-radius:2px;"></div></div>
        </div>`;
    }).join('');
}

async function drillIntoTechnique(techId, techName, alertCount) {
    document.getElementById('technique-modal').classList.add('active');
    document.getElementById('technique-modal-title').innerHTML = `<span style="color:var(--accent-purple);font-family:'IBM Plex Mono',monospace;">${techId}</span> — ${techName}`;
    document.getElementById('technique-modal-sub').innerText   = 'MITRE ATT&CK Technique';
    document.getElementById('technique-modal-count').innerText = alertCount.toLocaleString() + ' alerts';
    document.getElementById('technique-modal-loading').style.display      = 'block';
    document.getElementById('technique-modal-table-wrap').style.display   = 'none';
    document.getElementById('technique-modal-empty').style.display        = 'none';
    document.getElementById('technique-modal-showing').innerText          = '';
    ['tm-stat-total', 'tm-stat-ips', 'tm-stat-agents', 'tm-stat-critical'].forEach(id => document.getElementById(id).innerText = '—');

    const timeFilter = mitreDaysFilter > 0 ? { range: { "@timestamp": { gte: `now-${mitreDaysFilter}d/d` } } } : { match_all: {} };
    try {
        const res = await fetch(`${PROXY_URL}/${WAZUH_INDEX}/_search`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ size: 200, sort: [{ "@timestamp": { order: "desc" } }], query: { bool: { must: [timeFilter, { term: { "rule.mitre.id": techId } }] } }, _source: ["@timestamp", "data.srcip", "agent.name", "rule.id", "rule.level", "rule.description", "rule.mitre.tactic", "rule.mitre.id"] })
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data  = await res.json();
        const hits  = data.hits?.hits || [], total = data.hits?.total?.value || 0;
        document.getElementById('technique-modal-loading').style.display = 'none';
        if (!hits.length) { document.getElementById('technique-modal-empty').style.display = 'block'; return; }

        const uIPs    = new Set(hits.map(h => h._source?.data?.srcip).filter(Boolean)).size;
        const uAgents = new Set(hits.map(h => h._source?.agent?.name).filter(Boolean)).size;
        const crit    = hits.filter(h => (h._source?.rule?.level || 0) >= 15).length;
        document.getElementById('tm-stat-total').innerText   = total.toLocaleString();
        document.getElementById('tm-stat-ips').innerText     = uIPs;
        document.getElementById('tm-stat-agents').innerText  = uAgents;
        document.getElementById('tm-stat-critical').innerText = crit;
        document.getElementById('technique-modal-showing').innerText = `Showing ${hits.length} of ${total} logs`;

        document.getElementById('technique-modal-tbody').innerHTML = hits.map(h => {
            const src = h._source || {};
            const ts  = src['@timestamp'] ? new Date(src['@timestamp']).toLocaleString('en-US', { timeZone: 'Africa/Cairo', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true }) : '—';
            const ip  = src.data?.srcip || '—', agent = src.agent?.name || '—', rId = src.rule?.id || '—', lvl = src.rule?.level || '—', desc = src.rule?.description || '—';
            const lvlC = lvl >= 15 ? 'var(--accent-red)' : lvl >= 10 ? 'var(--accent-orange)' : 'var(--accent-blue)';
            return `<tr style="border-bottom:1px solid var(--border-color);">
                <td style="padding:10px 12px;font-size:11px;color:#8b949e;font-family:'IBM Plex Mono',monospace;white-space:nowrap;">${ts}</td>
                <td style="padding:10px 12px;white-space:nowrap;">${ip !== '—' ? `<a href="https://www.virustotal.com/gui/ip-address/${ip}/detection" target="_blank" style="color:var(--accent-red);text-decoration:none;font-family:'IBM Plex Mono',monospace;font-size:12px;">${ip}</a>` : '—'}</td>
                <td style="padding:10px 12px;color:var(--accent-blue);font-size:12px;">${agent}</td>
                <td style="padding:10px 12px;font-family:'IBM Plex Mono',monospace;color:var(--accent-purple);font-size:12px;">${rId}</td>
                <td style="padding:10px 12px;white-space:nowrap;"><span style="color:${lvlC};font-weight:700;font-size:12px;">Lvl ${lvl}</span></td>
                <td style="padding:10px 12px;font-size:12px;max-width:280px;white-space:normal;line-height:1.4;">${desc}</td>
                <td style="padding:10px 12px;"><button class="btn btn-sm" onclick="openCaseFromAlert('${ip}',${lvl * 6})">+ Case</button></td>
            </tr>`;
        }).join('');
        document.getElementById('technique-modal-table-wrap').style.display = 'block';
    } catch (err) {
        document.getElementById('technique-modal-loading').style.display = 'none';
        document.getElementById('technique-modal-empty').style.display   = 'block';
        document.getElementById('technique-modal-empty').innerText = `❌ Error: ${err.message}`;
    }
}

function closeTechniqueModal() {
    document.getElementById('technique-modal').classList.remove('active');
}

function buildMitreRulesTable() {
    const rules = [
        { ruleId:'100050', mitreId:'T1110.001', tactic:'Credential Access',    technique:'Password Guessing',          desc:'SSH invalid/non-existent user attempt',         severity:15 },
        { ruleId:'100051', mitreId:'T1110',     tactic:'Credential Access',    technique:'Brute Force',                desc:'Multiple SSH invalid user attempts',             severity:15 },
        { ruleId:'100060', mitreId:'—',         tactic:'Credential Access',    technique:'Brute Force',                desc:'Windows failed logon attempt',                  severity:14 },
        { ruleId:'100100', mitreId:'T1021.001', tactic:'Lateral Movement',     technique:'Remote Desktop Protocol',    desc:'RDP failed logon attempt',                      severity:14 },
        { ruleId:'100061', mitreId:'T1110',     tactic:'Credential Access',    technique:'Brute Force',                desc:'Multiple Windows failed logons',                 severity:15 },
        { ruleId:'100110', mitreId:'T1548.003', tactic:'Privilege Escalation', technique:'Sudo and Sudo Caching',      desc:'Sudo authentication failure',                   severity:5  },
        { ruleId:'100111', mitreId:'T1548.003 / T1110.001', tactic:'Privilege Escalation', technique:'Sudo Brute Force', desc:'Multiple failed sudo attempts',               severity:15 },
        { ruleId:'100112', mitreId:'T1098',     tactic:'Persistence',          technique:'Account Manipulation',       desc:'User added to SUDO/ROOT group',                 severity:15 },
        { ruleId:'100120', mitreId:'T1059',     tactic:'Execution',            technique:'Command & Scripting',        desc:'Suspicious file creation in malware path',      severity:14 },
        { ruleId:'100121', mitreId:'T1059.001 / T1218', tactic:'Defense Evasion', technique:'System Binary Proxy Exec', desc:'Suspicious/malicious process execution',      severity:15 },
        { ruleId:'100113', mitreId:'T1565.001', tactic:'Impact',               technique:'Stored Data Manipulation',   desc:'Sensitive file modified/created/deleted',       severity:15 },
    ];
    document.getElementById('mitre-rules-tbody').innerHTML = rules.map(r =>
        `<tr>
            <td style="font-family:'IBM Plex Mono',monospace;color:var(--accent-blue);">${r.ruleId}</td>
            <td style="font-family:'IBM Plex Mono',monospace;color:var(--accent-purple);">${r.mitreId}</td>
            <td>${r.tactic}</td>
            <td>${r.technique}</td>
            <td style="font-size:13px;">${r.desc}</td>
            <td><span style="color:${r.severity >= 15 ? 'var(--accent-red)' : r.severity >= 10 ? 'var(--accent-orange)' : 'var(--accent-blue)'};font-weight:700;">Level ${r.severity}</span></td>
        </tr>`).join('');
}

function showMitreStaticFallback() {
    const fd = [
        { tactic:'Credential Access', count:1491 }, { tactic:'Lateral Movement',    count:1015 },
        { tactic:'Defense Evasion',   count:833  }, { tactic:'Privilege Escalation', count:814  },
        { tactic:'Persistence',       count:239  }, { tactic:'Initial Access',       count:231  },
        { tactic:'Impact',            count:195  }, { tactic:'Execution',            count:1    },
    ];
    const gt = fd.reduce((s, d) => s + d.count, 0);
    document.getElementById('ms-total-alerts').innerText = gt.toLocaleString() + '*';
    document.getElementById('ms-tactics').innerText      = fd.length;
    document.getElementById('ms-techniques').innerText   = '—';
    document.getElementById('ms-top-tactic').innerText   = fd[0].tactic;
    document.getElementById('mitre-live-wrapper').style.display = 'flex';
    const mc = fd[0].count;
    document.getElementById('mitre-tactics-list').innerHTML = fd.map(d => {
        const fp = ((d.count / mc) * 100).toFixed(0);
        const cc = d.count >= 500 ? 'tactic-count-critical' : d.count >= 100 ? 'tactic-count-high' : d.count > 0 ? 'tactic-count-low' : 'tactic-count-zero';
        const bc = d.count >= 500 ? 'var(--accent-red)' : d.count >= 100 ? 'var(--accent-orange)' : 'var(--accent-blue)';
        return `<div class="tactic-row" style="cursor:default;">
            <div><div class="tactic-row-name">${d.tactic}</div><div class="tactic-heatbar"><div class="tactic-heatbar-fill" style="width:${fp}%;background:${bc};"></div></div></div>
            <div class="tactic-row-count ${cc}">${d.count.toLocaleString()}</div>
        </div>`;
    }).join('');
    document.getElementById('mitre-techniques-grid').innerHTML = '<div style="color:#8b949e;font-size:13px;padding:20px;">⚠️ Static fallback — connect Elasticsearch for live technique data.</div>';
    document.getElementById('mitre-last-updated').innerText = '⚠️ Static fallback data';
}