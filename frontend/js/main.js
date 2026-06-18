// ==================== TABS & MISC ====================
function switchTab(tabName, btn) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('tab-' + tabName).classList.add('active');
    if (btn) btn.classList.add('active');
    if (tabName === 'analytics') buildAnalyticsCharts();
    if (tabName === 'mitre')     { buildMitreRulesTable(); loadMitreData(7, document.querySelector('.mitre-toolbar .active-range')); }
    if (tabName === 'admin')     renderAnalystCards();
    if (tabName === 'search')    initSearchDefaults();
}

function triggerManualRefresh() {
    const btn = document.getElementById('refresh-btn');
    let deg = 0;
    btn.style.transition = 'transform 0.1s linear';
    const t = setInterval(() => { deg += 45; btn.style.transform = `rotate(${deg}deg)`; }, 100);
    fetchLiveAlerts().finally(() => {
        clearInterval(t);
        btn.style.transform = 'rotate(360deg)';
        setTimeout(() => { btn.style.transform = ''; btn.style.transition = ''; }, 300);
    });
}

// ==================== INIT ====================
populateLoginDropdown();