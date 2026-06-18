// ==================== MAP ====================
let map, attackerMarkers;

function initMap() {
    map = L.map('mapid').setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        attribution: '&copy; OpenStreetMap &copy; CARTO'
    }).addTo(map);
    attackerMarkers = L.layerGroup().addTo(map);
}