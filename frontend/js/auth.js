// ==================== AUTH ====================
function getAnalystList() {
    const s = localStorage.getItem('soc_analysts');
    if (s) return JSON.parse(s);
    const d = [{ name:'Admin', username:'admin', password:'admin123', role:'Admin', color:'#ff4444' }];
    localStorage.setItem('soc_analysts', JSON.stringify(d));
    return d;
}

function saveAnalystList(l) {
    localStorage.setItem('soc_analysts', JSON.stringify(l));
}

function populateLoginDropdown() {
    const sel = document.getElementById('login-username');
    sel.innerHTML = '<option value="">Select your account...</option>' +
        getAnalystList().map(a => `<option value="${a.username}">${a.name} (${a.username})</option>`).join('');
}

function handleLogin() {
    const u = document.getElementById('login-username').value;
    const p = document.getElementById('login-password').value;
    const e = document.getElementById('login-error');
    if (!u) { e.innerText = '⚠️ Select your account.'; return; }
    if (!p) { e.innerText = '⚠️ Enter your password.'; return; }
    const user = getAnalystList().find(a => a.username === u && a.password === p);
    if (!user) { e.innerText = '❌ Incorrect password.'; return; }
    sessionStorage.setItem('soc_current_user', JSON.stringify(user));
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('main-dashboard').style.display = 'block';
    document.getElementById('analyst-name-display').innerText  = user.name;
    document.getElementById('analyst-role-display').innerText  = user.role;
    document.getElementById('analyst-avatar').innerText        = user.name.charAt(0).toUpperCase();
    document.getElementById('analyst-avatar').style.background = user.color || '#58a6ff';
    if (user.role === 'Admin') document.getElementById('admin-tab-btn').style.display = 'inline-block';
    initMap();
    loadCasesFromMongoDB();
    fetchLiveAlerts();
    setInterval(fetchLiveAlerts, 10000);
}

function handleLogout() {
    if (!confirm('Logout?')) return;
    sessionStorage.removeItem('soc_current_user');
    document.getElementById('login-screen').classList.remove('hidden');
    document.getElementById('main-dashboard').style.display = 'none';
    document.getElementById('login-password').value = '';
    document.getElementById('login-error').innerText = '';
    document.getElementById('admin-tab-btn').style.display = 'none';
}

function getLoggedInUser() {
    const s = sessionStorage.getItem('soc_current_user');
    return s ? JSON.parse(s) : null;
}

function addNewAnalyst() {
    const name     = document.getElementById('new-analyst-name').value.trim();
    const username = document.getElementById('new-analyst-username').value.trim();
    const password = document.getElementById('new-analyst-password').value.trim();
    const role     = document.getElementById('new-analyst-role').value;
    if (!name || !username || !password) { alert('Fill all fields.'); return; }
    const list = getAnalystList();
    if (list.find(a => a.username === username)) { alert('Username exists!'); return; }
    list.push({ name, username, password, role, color: avatarColors[list.length % avatarColors.length] });
    saveAnalystList(list);
    ['new-analyst-name','new-analyst-username','new-analyst-password'].forEach(id => document.getElementById(id).value = '');
    renderAnalystCards();
    populateLoginDropdown();
    alert(`✅ "${name}" added!`);
}

function removeAnalyst(username) {
    if (username === 'admin') { alert('Cannot delete default admin!'); return; }
    if (!confirm(`Delete "${username}"?`)) return;
    saveAnalystList(getAnalystList().filter(a => a.username !== username));
    renderAnalystCards();
    populateLoginDropdown();
}

function renderAnalystCards() {
    document.getElementById('analysts-list').innerHTML = getAnalystList().map(a => `
        <div class="analyst-card">
            <div class="analyst-card-avatar" style="background:${a.color||'#58a6ff'};">${a.name.charAt(0)}</div>
            <div class="analyst-card-info">
                <div class="analyst-card-name">${a.name}</div>
                <div class="analyst-card-role">${a.role} · @${a.username}</div>
            </div>
            ${a.username !== 'admin'
                ? `<button class="analyst-card-del" onclick="removeAnalyst('${a.username}')">🗑</button>`
                : '<span style="font-size:12px;color:var(--accent-orange);">👑</span>'}
        </div>`).join('');
}