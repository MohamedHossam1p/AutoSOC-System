// ==================== CASES — MongoDB ====================
async function loadCasesFromMongoDB() {
    try {
        const res = await fetch(`${CASES_API}/cases`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        caseList = data.map(c => ({ ...c, id: c.case_id || c.id || c._id }));
    } catch (e) {
        console.warn('MongoDB load failed, using localStorage fallback:', e);
        caseList = JSON.parse(localStorage.getItem('soc_cases') || '[]');
    }
    renderCasesTable();
    refreshCaseCounters();
    if (alertRows.length) renderSortedTable();
}

function refreshCaseCounters() {
    const open   = caseList.filter(c => c.status === 'Open').length;
    const inv    = caseList.filter(c => c.status === 'Investigating').length;
    const closed = caseList.filter(c => c.status === 'Closed').length;
    document.getElementById('stat-open-cases').innerText   = open;
    document.getElementById('stat-closed-cases').innerText = closed;
    document.getElementById('cm-total').innerText          = caseList.length;
    document.getElementById('cm-open').innerText           = open;
    document.getElementById('cm-investigating').innerText  = inv;
    document.getElementById('cm-closed').innerText         = closed;
    document.getElementById('open-cases-badge').innerText  = open + inv;
}

function renderCasesTable() {
    const sf = document.getElementById('case-filter-status').value;
    const pf = document.getElementById('case-filter-priority').value;
    const st = (document.getElementById('case-search').value || '').toLowerCase();
    const filtered = caseList.filter(c => {
        if (sf !== 'all' && c.status !== sf) return false;
        if (pf !== 'all' && c.priority !== pf) return false;
        if (st && !JSON.stringify(c).toLowerCase().includes(st)) return false;
        return true;
    });
    if (!filtered.length) {
        document.getElementById('cases-tbody').innerHTML = '<tr><td colspan="8" class="empty-state">No cases match the filter.</td></tr>';
        return;
    }
    document.getElementById('cases-tbody').innerHTML = filtered.map(c => `
        <tr>
            <td><span style="font-family:'IBM Plex Mono',monospace;color:var(--accent-blue);">${c.id}</span></td>
            <td>${c.title}</td>
            <td><a href="https://www.virustotal.com/gui/ip-address/${c.ip}/detection" target="_blank" class="ip-link" style="color:var(--accent-red);">${c.ip}</a></td>
            <td class="priority-${(c.priority || 'medium').toLowerCase()}">${c.priority}</td>
            <td><span class="status-badge status-${(c.status || 'open').toLowerCase()}">${c.status}</span></td>
            <td>${c.analyst || '—'}</td>
            <td style="font-size:12px;color:#8b949e;">${new Date(c.created).toLocaleString('en-US')}</td>
            <td style="display:flex;gap:5px;flex-wrap:wrap;">
                <button class="btn btn-sm" onclick="viewCaseDetails('${c.id}')">👁 View</button>
                <button class="btn btn-sm" onclick="editExistingCase('${c.id}')">✏️ Edit</button>
                <button class="btn btn-sm" style="color:var(--accent-red);" onclick="deleteCase('${c.id}')">🗑</button>
                ${c.status !== 'Closed' ? `<button class="btn btn-success" onclick="markCaseClosed('${c.id}')">✓ Close</button>` : ''}
                ${c.status === 'Open' ? `<button class="btn btn-warn" onclick="markCaseInvestigating('${c.id}')">🔍 Invest.</button>` : ''}
            </td>
        </tr>`).join('');
}

function openNewCaseModal() {
    activeCaseId = null;
    document.getElementById('modal-title').innerText = '📁 New Case';
    ['modal-case-title', 'modal-case-ip', 'modal-case-notes'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('modal-case-priority').value = 'High';
    document.getElementById('modal-case-status').value   = 'Open';
    const u = getLoggedInUser();
    document.getElementById('modal-case-analyst').value = u ? u.name : '';
    document.getElementById('case-modal').classList.add('active');
}

function openCaseFromAlert(ip, riskScore) {
    activeCaseId = null;
    document.getElementById('modal-title').innerText        = '📁 New Case from Alert';
    document.getElementById('modal-case-title').value       = `Suspicious activity from ${ip}`;
    document.getElementById('modal-case-ip').value          = ip;
    document.getElementById('modal-case-priority').value    = riskScore >= 85 ? 'Critical' : riskScore >= 50 ? 'High' : 'Medium';
    document.getElementById('modal-case-status').value      = 'Open';
    const u = getLoggedInUser();
    document.getElementById('modal-case-analyst').value     = u ? u.name : '';
    document.getElementById('modal-case-notes').value       = `Auto-created from alert. Risk Score: ${riskScore}`;
    document.getElementById('case-modal').classList.add('active');
}

function editExistingCase(caseId) {
    const found = caseList.find(x => x.id === caseId);
    if (!found) return;
    activeCaseId = caseId;
    document.getElementById('modal-title').innerText        = '✏️ Edit Case ' + caseId;
    document.getElementById('modal-case-title').value       = found.title;
    document.getElementById('modal-case-ip').value          = found.ip;
    document.getElementById('modal-case-priority').value    = found.priority;
    document.getElementById('modal-case-status').value      = found.status;
    document.getElementById('modal-case-analyst').value     = found.analyst || '';
    document.getElementById('modal-case-notes').value       = '';
    document.getElementById('case-modal').classList.add('active');
}

async function saveCase() {
    const title    = document.getElementById('modal-case-title').value.trim();
    const ip       = document.getElementById('modal-case-ip').value.trim();
    const note     = document.getElementById('modal-case-notes').value.trim();
    const analyst  = document.getElementById('modal-case-analyst').value;
    const priority = document.getElementById('modal-case-priority').value;
    const status   = document.getElementById('modal-case-status').value;
    if (!title) { alert('Enter a title.'); return; }
    try {
        if (activeCaseId) {
            await fetch(`${CASES_API}/cases/${activeCaseId}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title, ip, priority, status, analyst }) });
            if (note) await fetch(`${CASES_API}/cases/${activeCaseId}/notes`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: note, author: analyst }) });
        } else {
            await fetch(`${CASES_API}/cases`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title, ip, priority, status, analyst, notes: note ? [{ text: note, author: analyst, time: new Date().toISOString() }] : [] }) });
        }
        closeCaseModal();
        await loadCasesFromMongoDB();
    } catch (e) { alert('Failed to save case: ' + e.message); }
}

function viewCaseDetails(caseId) {
    const found = caseList.find(x => x.id === caseId);
    if (!found) return;
    openCaseId = caseId;
    document.getElementById('view-modal-title').innerText = `📁 ${found.id} — ${found.title}`;
    document.getElementById('view-modal-content').innerHTML = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:15px;">
            <div><span style="color:#8b949e;font-size:12px;">IP</span><br><span style="color:var(--accent-red);font-family:'IBM Plex Mono',monospace;">${found.ip}</span></div>
            <div><span style="color:#8b949e;font-size:12px;">Status</span><br><span class="status-badge status-${(found.status || 'open').toLowerCase()}">${found.status}</span></div>
            <div><span style="color:#8b949e;font-size:12px;">Priority</span><br><span class="priority-${(found.priority || 'medium').toLowerCase()}">${found.priority}</span></div>
            <div><span style="color:#8b949e;font-size:12px;">Analyst</span><br>${found.analyst || '—'}</div>
            <div><span style="color:#8b949e;font-size:12px;">Created</span><br>${new Date(found.created).toLocaleString()}</div>
        </div>`;
    renderCaseNotes(found);
    document.getElementById('view-modal').classList.add('active');
}

function renderCaseNotes(c) {
    const tl    = document.getElementById('notes-timeline');
    const notes = c.notes || [];
    if (!notes.length) { tl.innerHTML = '<p style="color:#8b949e;font-size:13px;">No notes yet.</p>'; return; }
    tl.innerHTML = notes.slice().reverse().map(n =>
        `<div class="note-item"><div class="note-meta">${n.author} — ${new Date(n.time).toLocaleString()}</div><div class="note-text">${n.text}</div></div>`
    ).join('');
}

async function submitNoteToCase() {
    const text = document.getElementById('new-note-input').value.trim();
    if (!text || !openCaseId) return;
    const found   = caseList.find(x => x.id === openCaseId);
    const analyst = found?.analyst || getLoggedInUser()?.name || 'Analyst';
    try {
        await fetch(`${CASES_API}/cases/${openCaseId}/notes`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text, author: analyst }) });
        document.getElementById('new-note-input').value = '';
        await loadCasesFromMongoDB();
        const updated = caseList.find(x => x.id === openCaseId);
        if (updated) renderCaseNotes(updated);
    } catch (e) { console.error('submitNote failed:', e); }
}

async function markCaseClosed(id) {
    try { await fetch(`${CASES_API}/cases/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: 'Closed' }) }); await loadCasesFromMongoDB(); } catch (e) { console.error(e); }
}

async function markCaseInvestigating(id) {
    try { await fetch(`${CASES_API}/cases/${id}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status: 'Investigating' }) }); await loadCasesFromMongoDB(); } catch (e) { console.error(e); }
}

async function deleteCase(id) {
    if (!confirm('Delete this case?')) return;
    try { await fetch(`${CASES_API}/cases/${id}`, { method: 'DELETE' }); await loadCasesFromMongoDB(); } catch (e) { console.error(e); }
}

function closeCaseModal()  { document.getElementById('case-modal').classList.remove('active'); }
function closeViewModal()  { document.getElementById('view-modal').classList.remove('active'); }

document.getElementById('case-filter-status').onchange   = renderCasesTable;
document.getElementById('case-filter-priority').onchange = renderCasesTable;
document.getElementById('case-search').oninput           = renderCasesTable;