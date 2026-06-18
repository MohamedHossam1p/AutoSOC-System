// ==================== CONFIG ====================
const HOST = window.location.hostname;
const PROXY_URL   = `http://${HOST}:9202`;
const WAZUH_INDEX = "wazuh-alerts-4.x-*";
const LIVE_URL    = `http://${HOST}:9202`;
const LIVE_INDEX  = "soc-live-alerts";
const CASES_API   = `http://${HOST}:9205`;

// ==================== GLOBAL STATE ====================
let alertRows     = [];
let groupedAlerts = [];
let caseList      = [];
let activeCaseId  = null;
let openCaseId    = null;
let currentSort   = 'time';
let mitreDaysFilter = 7;
let tacticBucketMap = {};
const avatarColors = ['#58a6ff','#2ea043','#f2a60c','#bc8cff','#ff4444','#36c5f0','#e91e8c'];