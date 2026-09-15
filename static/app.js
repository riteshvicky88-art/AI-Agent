/* =====================================================================
   NucleoSense — app.js   (Multi-device edition)
   Each device has its own API endpoint: /api/device/:id/ingest
   ===================================================================== */
(function () {
'use strict';

var API_BASE     = 'http://localhost:3000';
var sessionStart = Date.now();
var token        = null;
window._getToken  = function() { return token; }; // debug helper
var currentUser  = null;
var pollTimer    = null;
var chartInst    = {};
var demoMode     = true;

// Devices loaded from server — filled after login
var devices = [];

// Per-device state and history
var state   = {};
var history = {};

// ── DEMO USERS ────────────────────────────────────────────────────────
var DEMO = {
    'admin':    { pass:'admin123', name:'Admin User',  role:'administrator', initials:'AD' },
    'operator': { pass:'op456',    name:'Op Engineer', role:'operator',      initials:'OP' }
};

// ── DEFAULT DEMO DATA per device type ────────────────────────────────
// Used when device is not connected — gives realistic starting values
var DEMO_DATA = {
    temp:    { pt100_temp:79.3,  raw_adc1:2841 },
    vacuum:  { pressure_kpa:-84.6, vacuum_pct:84.6, raw_adc2:1890 },
    motor:   { rpm:1497,  current_ma:488,  supply_v:24.05 },
    motor2:  { rpm:2988,  current_ma:503,  supply_v:24.05 },
    // Map device IDs to demo data as fallback
    pt100_01:  { pt100_temp:79.3,  raw_adc1:2841 },
    vac_01:    { pressure_kpa:-84.6, vacuum_pct:84.6, raw_adc2:1890 },
    motor_01:  { rpm:1497,  current_ma:488,  supply_v:24.05 },
    motor_02:  { rpm:2988,  current_ma:503,  supply_v:24.05 },
    generic:   { value:0.0 }
};

// Noise levels for simulation (per field)
var FIELD_NOISE = {
    pt100_temp:   { noise:0.08, lag:0.05 },
    pressure_kpa: { noise:0.25, lag:0.08 },
    vacuum_pct:   { noise:0.25, lag:0.08 },
    rpm:          { noise:3.5,  lag:0.12 },
    current_ma:   { noise:2.0,  lag:0.10 },
    supply_v:     { noise:0.02, lag:0.02 },
    raw_adc1:     { noise:2.0,  lag:0.05 },
    raw_adc2:     { noise:3.0,  lag:0.05 }
};

// ── ICON / STYLE MAPS ─────────────────────────────────────────────────
var typeIcon = {
    temp:'ph-thermometer', vacuum:'ph-gauge',
    motor:'ph-fan', motor2:'ph-gear', generic:'ph-cpu'
};
var typeColor = {
    temp:'#ff6b7a', vacuum:'var(--amber)', motor:'var(--accent)',
    motor2:'var(--purple)', generic:'var(--text2)'
};
var fieldStyle = {
    pt100_temp:   { icon:'ph-thermometer',     bg:'rgba(255,71,87,0.14)',  fg:'#ff6b7a',         label:'Process Temperature', unit:'°C'  },
    pressure_kpa: { icon:'ph-gauge',           bg:'rgba(255,179,0,0.12)', fg:'var(--amber)',     label:'Vacuum Pressure',     unit:'kPa' },
    vacuum_pct:   { icon:'ph-chart-pie',       bg:'rgba(0,212,255,0.1)',  fg:'var(--accent)',    label:'Vacuum Level',        unit:'%'   },
    rpm:          { icon:'ph-fan',             bg:'rgba(0,212,255,0.12)', fg:'var(--accent)',    label:'Motor Speed',         unit:'RPM' },
    current_ma:   { icon:'ph-lightning',       bg:'rgba(255,179,0,0.12)', fg:'var(--amber)',     label:'Drive Current',       unit:'mA'  },
    supply_v:     { icon:'ph-plug',            bg:'rgba(0,230,118,0.1)',  fg:'var(--green)',     label:'Supply Voltage',      unit:'V'   },
    raw_adc1:     { icon:'ph-wave-sine',       bg:'rgba(255,255,255,0.06)', fg:'var(--text2)',   label:'Raw ADC 1',           unit:''    },
    raw_adc2:     { icon:'ph-wave-sine',       bg:'rgba(255,255,255,0.06)', fg:'var(--text2)',   label:'Raw ADC 2',           unit:''    }
};
function getFieldStyle(key) {
    return fieldStyle[key] || { icon:'ph-sliders', bg:'rgba(255,255,255,0.06)', fg:'var(--text2)', label:key, unit:'' };
}

// ── HELPERS ───────────────────────────────────────────────────────────
function barColor(pv, nominal) {
    if (nominal === undefined || nominal === 0) return 'var(--accent)';
    var d = Math.abs(pv - nominal) / Math.max(Math.abs(nominal), 1) * 100;
    return d < 2 ? 'var(--green)' : d < 8 ? 'var(--amber)' : 'var(--red)';
}
function fmtVal(v, unit) {
    if (v === undefined || v === null || isNaN(Number(v))) return '—';
    if (unit === 'RPM') return Math.round(Number(v)).toLocaleString();
    if (unit === 'mA')  return Math.round(Number(v)).toString();
    if (unit === 'V')   return Number(v).toFixed(2);
    if (unit === 'kPa') return Number(v).toFixed(1);
    if (unit === '%')   return Number(v).toFixed(1);
    if (unit === '°C')  return Number(v).toFixed(1);
    if (!unit)          return Math.round(Number(v)).toString();
    return Number(v).toFixed(1);
}
function parseTS(ts) {
    if (!ts) return NaN;
    // Handle both "2024-01-01T12:00:00.000Z" and "2024-01-01 12:00:00" formats
    var d = new Date(ts);
    if (isNaN(d.getTime())) d = new Date(ts.replace(' ', 'T') + 'Z');
    return d.getTime();
}
function timeSince(ts) {
    if (!ts) return 'never';
    var t   = parseTS(ts);
    if (isNaN(t)) return 'just now';
    var sec = Math.floor((Date.now() - t) / 1000);
    if (sec < 0)   return 'just now';
    if (sec < 5)   return 'just now';
    if (sec < 60)  return sec + 's ago';
    if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
    return Math.floor(sec / 3600) + 'h ago';
}
function isOnline(ts) {
    if (!ts) return false;
    var t = parseTS(ts);
    return !isNaN(t) && (Date.now() - t) < 10000;
}

// ── INIT STATE ────────────────────────────────────────────────────────
function initDeviceState(device) {
    if (!state[device.id]) {
        // Try demo data by ID first, then by type, then generic
        var demo = DEMO_DATA[device.id]
                || DEMO_DATA[device.type]
                || DEMO_DATA.generic;
        // Deep copy so mutations don't affect the template
        var dataCopy = JSON.parse(JSON.stringify(demo));
        state[device.id] = {
            data:      dataCopy,
            lastSeen:  null,
            online:    false,
            showGraph: false
        };
    }
    if (!history[device.id]) {
        history[device.id] = {};
        var data = state[device.id].data;
        Object.keys(data).forEach(function (k) {
            if (typeof data[k] !== 'number') return;
            var n = (FIELD_NOISE[k] || { noise:0.5 }).noise;
            // Pre-fill history with realistic spread so trend charts look live
            history[device.id][k] = Array(20).fill(0).map(function () {
                return Number(data[k]) + (Math.random() - 0.5) * n * 4;
            });
        });
    }
}

// ── RENDER DASHBOARD ──────────────────────────────────────────────────
var dashboardEl = document.getElementById('dashboard');

function render() {
    var html    = '';
    var alarms  = 0;
    var online  = 0;

    if (demoMode) {
        html += '<div style="grid-column:1/-1;display:flex;align-items:center;gap:10px;'
            + 'padding:10px 16px;background:rgba(255,179,0,0.07);'
            + 'border:1px solid rgba(255,179,0,0.25);border-radius:8px;'
            + 'margin-bottom:4px;font-size:0.78rem;color:var(--amber);font-family:var(--mono)">'
            + '<i class="ph ph-warning" style="font-size:1rem;flex-shrink:0"></i>'
            + '<span>DEMO MODE &mdash; Devices not connected. Showing simulated data. '
            + 'Connect devices to see live readings.</span></div>';
    }

    if (devices.length === 0) {
        html += '<div style="grid-column:1/-1;text-align:center;padding:48px;color:var(--text2)">'
            + '<i class="ph ph-plugs-connected" style="font-size:3rem;display:block;margin-bottom:12px;opacity:0.4"></i>'
            + '<div style="font-size:0.9rem;font-weight:600">No devices registered</div>'
            + '<div style="font-size:0.78rem;margin-top:6px;font-family:var(--mono)">'
            + 'Click the <b>+</b> button to add your first STM32 device</div></div>';
    }

    devices.forEach(function (device) {
        initDeviceState(device);
        var s   = state[device.id];
        var data = s.data || {};
        if (s.online) online++;

        var cardClass = !s.online ? (demoMode ? 'online' : 'offline') : 'online';
        var icon      = typeIcon[device.type] || 'ph-cpu';
        var lastTs    = s.lastSeen ? timeSince(s.lastSeen) : (demoMode ? 'Demo mode' : 'No data');

        // Only show numeric fields as param rows
        var numFields = Object.keys(data).filter(function (k) {
            return typeof data[k] === 'number' && !k.startsWith('_');
        });

        var paramsHtml = numFields.map(function (k) {
            var fs   = getFieldStyle(k);
            var val  = data[k];
            var prev = (history[device.id] && history[device.id][k])
                ? history[device.id][k].slice(-2)[0] : val;
            var trend = val > prev + 0.1 ? '▲' : val < prev - 0.1 ? '▼' : '–';
            var trendColor = trend === '▲' ? 'var(--red)' : trend === '▼' ? 'var(--green)' : 'var(--text3)';
            // Scale bar correctly based on field type
            var maxVal = {'rpm':3000,'pt100_temp':200,'pressure_kpa':101,
                          'vacuum_pct':100,'current_ma':1000,'supply_v':28,
                          'raw_adc1':4096,'raw_adc2':4096}[k] || 200;
            var fillW = Math.min(100, Math.max(0, (Math.abs(val) / maxVal) * 100));
            var fillC = 'var(--green)'; // stable green in demo
            var profItem = getActiveProfileItemFor(device.id, k);
            var spHtml = profItem
                ? ('&nbsp;&nbsp;<span class="sv-tag">SP</span><span class="sv-val">' + fmtVal(profItem.value, fs.unit) + ' ' + fs.unit + '</span>')
                : '';
            var profChip = profItem
                ? ('&nbsp;&nbsp;<span class="pv-tag" style="background:rgba(0,212,255,0.16);color:var(--accent);cursor:pointer;padding:2px 7px;border-radius:6px;border:1px solid rgba(0,212,255,0.3)" '
                   + 'title="Setpoint from active profile: ' + escHtml(profItem.profileName) + '" '
                   + 'onclick="showPage(\'profiles\');return false;"><i class="ph ph-flask-fill" style="font-size:0.68rem;vertical-align:-1px"></i>&nbsp;' + escHtml(profItem.profileName) + '</span>')
                : '';

            return '<div class="param-row">'
                + '<div class="param-icon" style="background:' + fs.bg + ';color:' + fs.fg + '">'
                + '<i class="ph ' + fs.icon + '"></i></div>'
                + '<div class="param-body">'
                + '<div class="param-label">' + fs.label + '</div>'
                + '<div class="pv-sv">'
                + '<span class="pv-tag">PV</span>'
                + '<span class="pv-val">' + fmtVal(val, fs.unit) + '</span>'
                + '<span class="pv-unit">' + fs.unit + '</span>'
                + '&nbsp;&nbsp;<span style="font-size:0.75rem;color:' + trendColor + ';font-family:var(--mono)">' + trend + '</span>'
                + spHtml
                + profChip
                + '</div>'
                + '<div class="progress-bar-wrap"><div class="progress-bar-fill" style="width:' + fillW + '%;background:' + fillC + '"></div></div>'
                + '</div>'
                + '</div>';
        }).join('');

        if (!paramsHtml) paramsHtml = '<div style="padding:16px;font-size:0.78rem;color:var(--text3);'
            + 'font-family:var(--mono);text-align:center">Waiting for first reading…</div>';

        var onlineIndicator = (s.online || demoMode)
            ? '<span class="status-pill online"><span class="chip-dot"></span>ONLINE</span>'
            : '<span class="status-pill offline"><span class="chip-dot"></span>OFFLINE</span>';

        var demoBadge = demoMode
            ? '<span style="font-size:0.6rem;font-family:var(--mono);font-weight:700;padding:2px 6px;'
              + 'border-radius:8px;background:rgba(255,179,0,0.12);color:var(--amber);'
              + 'border:1px solid rgba(255,179,0,0.28)">DEMO</span>'
            : '';

        var graphVis = (s && s.showGraph) ? 'visible' : '';

        html += '<div class="inst-card ' + cardClass + '" id="card-' + device.id + '">'
            + '<div class="card-head">'
            + '<div class="inst-icon" style="color:' + (typeColor[device.type]||'var(--accent)') + '">'
            + '<i class="ph ' + icon + '"></i></div>'
            + '<div class="inst-meta">'
            + '<div class="inst-name">' + device.name + '</div>'
            + '<div class="inst-id" style="font-family:var(--mono)">' + device.id + '</div>'
            + '</div>'
            + '<div class="card-head-right">' + demoBadge + onlineIndicator + '</div>'
            + '</div>'

            // Ambient strip — IP and device ID
            + '<div class="card-ambient">'
            + '<div class="amb-item"><i class="ph ph-wifi-high" style="color:' + (s.online||demoMode?'var(--green)':'var(--text3)') + '"></i>'
            + '&nbsp;<span class="amb-val">' + (device.ip || '—') + '</span></div>'
            + '<div class="amb-item"><i class="ph ph-tag" style="color:var(--accent2)"></i>'
            + '&nbsp;<span class="amb-val">' + (device.type || 'generic') + '</span></div>'
            + '<div class="amb-item" style="flex:2;overflow:hidden"><i class="ph ph-link" style="color:var(--text3)"></i>'
            + '&nbsp;<span style="font-family:var(--mono);font-size:0.62rem;color:var(--text3);'
            + 'white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block">'
            + '/api/device/' + device.id + '/ingest</span></div>'
            + '</div>'

            + '<div class="card-params">' + paramsHtml + '</div>'

            + '<div class="card-footer">'
            + '<div class="sync-time"><i class="ph ph-arrows-clockwise"></i>&nbsp;' + lastTs + '</div>'
            + '<button class="foot-btn" onclick="toggleGraph(\'' + device.id + '\')">'
            + '<i class="ph ph-chart-line"></i>&nbsp;Trend</button>'
            + '<button class="foot-btn" onclick="showDeviceInfo(\'' + device.id + '\')">'
            + '<i class="ph ph-info"></i>&nbsp;Info</button>'
            + '<button class="foot-btn export" onclick="exportCsv(\'' + device.id + '\')">'
            + '<i class="ph ph-download-simple"></i>&nbsp;Export</button>'
            + '</div>'
            + '<div class="card-graph ' + graphVis + '" id="graph-' + device.id + '">'
            + '<div class="graph-wrap"><div class="graph-title">Live Trend — ' + device.name + ' (Last 40s)</div>'
            + '<canvas id="canvas-' + device.id + '" height="75"></canvas></div></div>'
            + '</div>';
    });

    dashboardEl.innerHTML = html;

    requestAnimationFrame(function () {
        devices.forEach(function (d) {
            if (state[d.id] && state[d.id].showGraph) drawGraph(d.id);
        });
    });

    // Stats
    document.getElementById('stat-total').textContent   = devices.length;
    document.getElementById('stat-online').textContent  = demoMode ? devices.length : online;
    document.getElementById('stat-alarms').textContent  = alarms;
    document.getElementById('inst-count').textContent   = devices.length;
    document.getElementById('active-count').textContent = demoMode ? devices.length : online;
    document.getElementById('alarm-count').textContent  = alarms;

    var sec = Math.floor((Date.now() - sessionStart) / 1000);
    document.getElementById('stat-uptime').textContent =
        Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm';
}

// ── FETCH ALL DEVICES LATEST DATA ─────────────────────────────────────
function fetchAllDevices() {
    fetch(API_BASE + '/api/devices/all-latest', {
        headers: { 'Authorization': 'Bearer ' + token }
    })
    .then(function (r) { return r.json(); })
    .then(function (result) {
        var anyOnline = false;
        Object.keys(result).forEach(function (id) {
            var entry = result[id];
            if (!state[id]) initDeviceState(entry.device);
            if (entry.data) {
                anyOnline = true;
                // Merge live data on top of existing state (keep demo fields as fallback)
                Object.keys(entry.data).forEach(function (k) {
                    if (!k.startsWith('_')) state[id].data[k] = entry.data[k];
                });
                state[id].online   = entry.online;
                state[id].lastSeen = entry.timestamp;
                // Update chart history with live values
                Object.keys(entry.data).forEach(function (k) {
                    if (typeof entry.data[k] !== 'number') return;
                    if (!history[id])    history[id]    = {};
                    if (!history[id][k]) history[id][k] = Array(20).fill(entry.data[k]);
                    history[id][k].push(entry.data[k]);
                    history[id][k].shift();
                });
            } else {
                // No data from device yet — keep demo data visible, mark offline
                state[id].online = false;
            }
        });
        if (anyOnline && demoMode) {
            demoMode = false;
            toast('STM32 connected — live data active', 'success');
        } else if (!anyOnline) {
            demoMode = true;
            simulateTick();
            return;
        }
        render();
    })
    .catch(function () {
        demoMode = true;
        simulateTick();
    });
    loadActiveProfileBanner();
}

var activeProfileCache = null;
function getActiveProfileItemFor(deviceId, paramId) {
    if (!activeProfileCache || !activeProfileCache.active || !activeProfileCache.profile) return null;
    var p = activeProfileCache.profile;
    var it = (p.items || []).find(function (x) { return x.device_id === deviceId && x.param_id === paramId; });
    return it ? { value: it.value, unit: it.unit, profileName: p.name } : null;
}
function loadActiveProfileBanner() {
    if (!token) return;
    fetch(API_BASE + '/api/profiles/active', { headers: { Authorization: 'Bearer ' + token } })
    .then(function (r) { return r.status === 401 ? null : r.json(); })
    .then(function (d) {
        var prevActive = activeProfileCache && activeProfileCache.active && activeProfileCache.profile ? activeProfileCache.profile.id : null;
        var nextActive = d && d.active && d.profile ? d.profile.id : null;
        activeProfileCache = d || null;
        renderActiveProfileBanner();
        if (prevActive !== nextActive) render();  // profile chips on cards depend on this
    })
    .catch(function () {});
}
function renderActiveProfileBanner() {
    var el = document.getElementById('active-profile-banner');
    if (!el) return;
    if (!activeProfileCache || !activeProfileCache.active || !activeProfileCache.profile) {
        el.style.cssText = 'display:flex;align-items:center;gap:10px;margin-bottom:14px;padding:10px 14px;border-radius:10px;background:var(--panel);border:1px solid var(--border);color:var(--text3);font-size:0.8rem';
        el.innerHTML = '<i class="ph ph-flask" style="font-size:1.1rem;opacity:0.5"></i> No profile currently active — devices are running on their last individually-set setpoints.'
            + ' <a href="#" onclick="showPage(\'profiles\');return false;" style="color:var(--accent);margin-left:auto;white-space:nowrap">Go to Profiles &rarr;</a>';
        return;
    }
    var p = activeProfileCache.profile;
    var lr = p.last_run;
    var itemsHtml = (p.items || []).map(function (it) {
        return '<span style="font-family:var(--mono);background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:2px 8px;margin-right:6px;display:inline-block;margin-bottom:4px">'
            + escHtml(it.device_id) + ' &middot; ' + escHtml(it.param_label || it.param_id) + ' = <span style="color:var(--accent)">' + it.value + ' ' + escHtml(it.unit || '') + '</span></span>';
    }).join('');
    el.style.cssText = 'display:flex;flex-direction:column;gap:6px;margin-bottom:14px;padding:12px 14px;border-radius:10px;background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.25)';
    el.innerHTML =
        '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'
        +   '<i class="ph ph-flask-fill" style="font-size:1.1rem;color:var(--accent)"></i>'
        +   '<span style="font-weight:700;font-size:0.85rem">Active Profile: ' + escHtml(p.name) + '</span>'
        +   '<span class="nav-badge" style="background:var(--green);color:#04140b">RUNNING</span>'
        +   (lr ? '<span style="font-size:0.72rem;color:var(--text3)">started ' + escHtml(lr.run_at) + ' by ' + escHtml(lr.run_by_name || lr.run_by) + '</span>' : '')
        +   '<a href="#" onclick="showPage(\'profiles\');return false;" style="color:var(--accent);margin-left:auto;font-size:0.76rem;white-space:nowrap">Manage &rarr;</a>'
        + '</div>'
        + '<div>' + itemsHtml + '</div>';
}

// ── LOAD DEVICE LIST FROM SERVER ─────────────────────────────────────
function loadDevices() {
    return fetch(API_BASE + '/api/devices', {
        headers: { 'Authorization': 'Bearer ' + token }
    })
    .then(function (r) { return r.json(); })
    .then(function (list) {
        devices = list;
        list.forEach(function (d) { initDeviceState(d); });
    })
    .catch(function () {
        // API offline — use built-in defaults
        devices = [
            { id:'pt100_01', name:'PT100 Temperature Sensor', type:'temp',   ip:'192.168.1.101' },
            { id:'vac_01',   name:'Vacuum Pressure Sensor',   type:'vacuum', ip:'192.168.1.102' },
            { id:'motor_01', name:'Motor 1 — RPM Controller', type:'motor',  ip:'192.168.1.103' },
            { id:'motor_02', name:'Motor 2 — RPM Controller', type:'motor2', ip:'192.168.1.104' }
        ];
        devices.forEach(function (d) { initDeviceState(d); });
    });
}

// ── SIMULATION ────────────────────────────────────────────────────────
function simulateTick() {
    var now = new Date().toLocaleTimeString();
    devices.forEach(function (device) {
        if (!state[device.id]) return;
        var data = state[device.id].data;
        state[device.id].lastSeen = now;
        Object.keys(data).forEach(function (k) {
            if (typeof data[k] !== 'number') return;
            var cfg   = FIELD_NOISE[k] || { noise:0.5, lag:0.05 };
            data[k]  += (Math.random() - 0.5) * cfg.noise * 2;
            if (!history[device.id]) history[device.id] = {};
            if (!history[device.id][k]) history[device.id][k] = Array(20).fill(data[k]);
            history[device.id][k].push(data[k]);
            history[device.id][k].shift();
        });
    });
    render();
}

// ── TREND GRAPH ───────────────────────────────────────────────────────
window.toggleGraph = function (id) {
    if (!state[id]) return;
    if (chartInst[id]) { chartInst[id].destroy(); delete chartInst[id]; }
    state[id].showGraph = !state[id].showGraph;
    render();
    if (state[id].showGraph) {
        requestAnimationFrame(function () {
            requestAnimationFrame(function () { drawGraph(id); });
        });
    }
};

function drawGraph(devId) {
    var h      = history[devId]; if (!h) return;
    var canvas = document.getElementById('canvas-' + devId); if (!canvas) return;
    if (canvas.offsetParent === null) return;
    if (chartInst[devId]) { chartInst[devId].destroy(); delete chartInst[devId]; }

    var numKeys = Object.keys(h).filter(function (k) { return Array.isArray(h[k]); }).slice(0, 3);
    if (!numKeys.length) return;

    var labels = [];
    for (var i = 0; i < 20; i++) labels.push(i === 19 ? 'now' : '-' + ((19 - i) * 2) + 's');

    var colors = ['rgb(0,212,255)', 'rgb(255,71,87)', 'rgb(0,230,118)', 'rgb(255,179,0)'];
    var datasets = numKeys.map(function (k, ci) {
        var fs = getFieldStyle(k);
        return {
            label: fs.label + (fs.unit ? ' (' + fs.unit + ')' : ''),
            data:  h[k].slice(),
            borderColor: colors[ci],
            backgroundColor: colors[ci].replace('rgb', 'rgba').replace(')', ',0.07)'),
            borderWidth: 1.5, pointRadius: 0, tension: 0.4, fill: true
        };
    });

    try {
        chartInst[devId] = new Chart(canvas, {
            type: 'line',
            data: { labels: labels, datasets: datasets },
            options: {
                responsive: true, animation: false,
                plugins: { legend: { labels: { color:'#7a8da8', font:{ size:9, family:'IBM Plex Mono' }, boxWidth:8 } } },
                scales: {
                    x: { ticks:{ color:'#4a5a72', font:{ size:8 } }, grid:{ color:'#1c2333' } },
                    y: { ticks:{ color:'#4a5a72', font:{ size:8, family:'IBM Plex Mono' } }, grid:{ color:'#1c2333' } }
                }
            }
        });
    } catch (e) { console.warn('Chart error', devId, e); }
}

// ── DEVICE INFO MODAL ─────────────────────────────────────────────────
window.showDeviceInfo = function (id) {
    var device = devices.find(function (d) { return d.id === id; });
    if (!device) return;
    var s = state[id];

    document.getElementById('info-title').textContent  = device.name;
    document.getElementById('info-id').textContent     = device.id;
    document.getElementById('info-type').textContent   = device.type;
    document.getElementById('info-ip').textContent     = device.ip || '—';
    document.getElementById('info-desc').textContent   = device.description || '—';
    document.getElementById('info-url').textContent    = 'POST ' + API_BASE + '/api/device/' + device.id + '/ingest';
    document.getElementById('info-seen').textContent   = s.lastSeen || 'Never';
    document.getElementById('info-status').textContent = (s.online || demoMode) ? 'Online' : 'Offline';

    // Example curl command
    var examplePayload = JSON.stringify(s.data || {}, null, 2);
    document.getElementById('info-curl').textContent =
        'curl -X POST ' + API_BASE + '/api/device/' + device.id + '/ingest \\\n'
        + '  -H "Content-Type: application/json" \\\n'
        + '  -d \'' + JSON.stringify(s.data || {}) + '\'';

    document.getElementById('info-modal').classList.add('open');
};

window.closeInfoModal = function () {
    document.getElementById('info-modal').classList.remove('open');
};

// ── ADD DEVICE MODAL ──────────────────────────────────────────────────
window.openAddModal = function () {
    document.getElementById('add-modal').classList.add('open');
    document.getElementById('new-dev-id').value   = '';
    document.getElementById('new-dev-name').value = '';
    document.getElementById('new-dev-ip').value   = '';
    document.getElementById('new-dev-desc').value = '';
    document.getElementById('add-dev-err').textContent = '';
};

window.closeAddModal = function () {
    document.getElementById('add-modal').classList.remove('open');
};

window.submitAddDevice = function () {
    var id   = document.getElementById('new-dev-id').value.trim();
    var name = document.getElementById('new-dev-name').value.trim();
    var type = document.getElementById('new-dev-type').value;
    var ip   = document.getElementById('new-dev-ip').value.trim();
    var desc = document.getElementById('new-dev-desc').value.trim();
    var err  = document.getElementById('add-dev-err');

    if (!id)   { err.textContent = 'Device ID is required'; return; }
    if (!name) { err.textContent = 'Device name is required'; return; }
    if (!/^[a-zA-Z0-9_]+$/.test(id)) { err.textContent = 'ID: letters, numbers and underscores only'; return; }

    err.textContent = '';

    fetch(API_BASE + '/api/devices', {
        method:  'POST',
        headers: { 'Content-Type':'application/json', 'Authorization':'Bearer ' + token },
        body:    JSON.stringify({ id, name, type, ip, description: desc })
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
        if (data.error) { err.textContent = data.error; return; }
        closeAddModal();
        toast('Device "' + name + '" registered', 'success');
        toast('Ingest URL: /api/device/' + id + '/ingest', 'info');
        // Add to local list and re-render
        var newDev = { id, name, type, ip, description: desc };
        devices.push(newDev);
        initDeviceState(newDev);
        render();
    })
    .catch(function () {
        // API offline — add locally in demo mode
        var newDev = { id, name, type, ip, description: desc };
        devices.push(newDev);
        initDeviceState(newDev);
        closeAddModal();
        toast('Device added (demo mode)', 'info');
        render();
    });
};

// ── EXPORT CSV ────────────────────────────────────────────────────────
window.exportCsv = function (id) {
    var device = devices.find(function (d) { return d.id === id; });
    var s      = state[id];
    if (!device || !s) return;
    var csv = 'Device,' + device.name + '\nID,' + id + '\nIP,' + (device.ip || '')
            + '\nIngest URL,' + API_BASE + '/api/device/' + id + '/ingest'
            + '\nTimestamp,' + new Date().toISOString()
            + '\nMode,' + (demoMode ? 'DEMO' : 'LIVE')
            + '\n\nField,Value\n';
    Object.keys(s.data || {}).forEach(function (k) {
        csv += k + ',' + s.data[k] + '\n';
    });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([csv], { type:'text/csv' }));
    a.download = id + '_' + new Date().toISOString().slice(0, 10) + '.csv';
    a.click();
    toast('Exported — ' + device.name, 'success');
};

// ── TOAST ─────────────────────────────────────────────────────────────
function toast(msg, type) {
    type = type || 'info';
    var icons = { success:'ph-check-circle', error:'ph-x-circle', info:'ph-info' };
    var cols  = { success:'var(--green)',     error:'var(--red)',   info:'var(--accent)' };
    var el = document.createElement('div');
    el.className = 'toast ' + type;
    el.innerHTML = '<i class="ph ' + icons[type] + '" style="color:' + cols[type] + ';font-size:1rem"></i><span>' + msg + '</span>';
    document.getElementById('toasts').appendChild(el);
    setTimeout(function () {
        el.style.opacity = '0'; el.style.transition = 'opacity 0.3s';
        setTimeout(function () { el.remove(); }, 300);
    }, 3000);
}

// ── CLOCK ─────────────────────────────────────────────────────────────
function updateClock() {
    document.getElementById('global-clock').textContent =
        new Date().toLocaleTimeString('en-IN', { hour12:false });
}

// ── LOGIN ─────────────────────────────────────────────────────────────
function doLogin() {
    var u     = document.getElementById('l-user').value.trim();
    var p     = document.getElementById('l-pass').value.trim();
    var errEl = document.getElementById('login-err');
    var btn   = document.getElementById('login-btn');
    errEl.textContent = '';
    if (!u || !p) { errEl.textContent = 'Enter username and password.'; return; }
    btn.textContent = 'Signing in...'; btn.disabled = true;

    fetch(API_BASE + '/api/login', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ username:u, password:p })
    })
    .then(function (r) { if (!r.ok) throw new Error('bad'); return r.json(); })
    .then(function (d) { token = d.token; currentUser = d.user; enterDashboard(); })
    .catch(function () {
        var demo = DEMO[u];
        if (demo && demo.pass === p) {
            token = 'demo_' + Math.random().toString(36).slice(2);
            currentUser = { username:u, name:demo.name, role:demo.role, initials:demo.initials };
            enterDashboard();
        } else {
            errEl.textContent = 'Invalid username or password.';
            btn.textContent = 'Sign In'; btn.disabled = false;
        }
    });
}

function enterDashboard() {
    document.getElementById('login-overlay').style.display = 'none';
    document.getElementById('sb-avatar').textContent  = currentUser.initials || currentUser.username[0].toUpperCase();
    document.getElementById('sb-name').textContent    = currentUser.name || currentUser.username;
    document.getElementById('sb-role').textContent    = currentUser.role || 'user';
    document.getElementById('session-label').textContent = 'Session: ' + currentUser.username + ' · v1.0';
    document.getElementById('login-btn').textContent  = 'Sign In';
    document.getElementById('login-btn').disabled     = false;

    // Show/hide admin-only controls
    if (currentUser.role === 'administrator') {
        document.getElementById('add-device-btn').style.display = 'flex';
    }

    toast('Welcome, ' + currentUser.name.split(' ')[0], 'success');

    loadDevices().then(function () {
        render();
        setTimeout(function () { toast('Demo mode — connect STM32 for live data', 'info'); }, 1000);
        pollTimer = setInterval(function () { updateClock(); fetchAllDevices(); }, 2000);
    });
}

function logout() {
    clearInterval(pollTimer); token = null; currentUser = null; location.reload();
}

// ── EVENT BINDINGS ────────────────────────────────────────────────────
document.getElementById('login-btn').addEventListener('click', doLogin);
document.getElementById('l-pass').addEventListener('keydown', function (e) { if (e.key === 'Enter') doLogin(); });
document.getElementById('l-user').addEventListener('keydown', function (e) { if (e.key === 'Enter') doLogin(); });
document.getElementById('logout-btn').addEventListener('click', logout);
document.getElementById('refresh-btn').addEventListener('click', fetchAllDevices);
document.getElementById('fs-btn').addEventListener('click', function () {
    document.documentElement.requestFullscreen && document.documentElement.requestFullscreen();
});
document.getElementById('add-device-btn').addEventListener('click', openAddModal);

// Close modals on backdrop click
document.getElementById('add-modal').addEventListener('click', function (e) {
    if (e.target === this) closeAddModal();
});
document.getElementById('info-modal').addEventListener('click', function (e) {
    if (e.target === this) closeInfoModal();
});
document.getElementById('profile-modal').addEventListener('click', function (e) {
    if (e.target === this) closeProfileModal();
});
document.getElementById('profile-start-modal').addEventListener('click', function (e) {
    if (e.target === this) closeProfileStartModal();
});
document.getElementById('delete-profile-modal').addEventListener('click', function (e) {
    if (e.target === this) closeDeleteProfileModal();
});

// ── BOOT ──────────────────────────────────────────────────────────────
updateClock();
setInterval(updateClock, 1000);



// ═══════════════════════════════════════════════════════════════════════
// AUDIT TRAIL
// ═══════════════════════════════════════════════════════════════════════

var auditOffset   = 0;
var auditTotal    = 0;
var currentPage   = 'dashboard';

// ── Page switching ─────────────────────────────────────────────────────
window.showPage = function (page) {
    currentPage = page;
    ['dashboard', 'audit', 'profiles'].forEach(function (p) {
        var el = document.getElementById('page-' + p);
        if (el) el.style.display = (p === page) ? '' : 'none';
    });

    // Update nav active state
    document.querySelectorAll('.nav-item').forEach(function (el) { el.classList.remove('active'); });
    var navEl = document.getElementById('nav-' + page);
    if (navEl) navEl.classList.add('active');

    // Update topbar title
    var titles = {
        dashboard: ['Instrument Overview',       'STM32F446RE · Real-time monitoring'],
        audit:     ['Audit Trail',               'Complete log of all user actions and system changes'],
        profiles:  ['Profiles',                  'Recipe programming — signed, multi-device setpoint bundles']
    };
    var t = titles[page] || titles.dashboard;
    document.getElementById('page-title').textContent    = t[0];
    document.getElementById('page-subtitle').textContent = t[1];

    if (page === 'audit') {
        auditOffset = 0;
        loadAuditSummary();
        loadAuditActors();
        loadAudit();
    }
    if (page === 'profiles') {
        loadProfiles();
    }
};

// ── Load audit summary stats ───────────────────────────────────────────
function loadAuditSummary() {
    fetch(API_BASE + '/api/audit/summary', { headers: { Authorization: 'Bearer ' + token } })
    .then(function (r) { return r.json(); })
    .then(function (d) {
        document.getElementById('audit-total').textContent  = d.total || 0;

        var logins  = (d.by_type.find(function(x){ return x.event_type === 'login'; }) || {}).count || 0;
        var deletes = (d.by_type.filter(function(x){ return x.event_type.startsWith('delete'); })
                                .reduce(function(a,x){ return a + x.count; }, 0));
        var changes = (d.by_type.filter(function(x){
            return x.event_type.startsWith('create') || x.event_type.startsWith('update') || x.event_type === 'ack_alert';
        }).reduce(function(a,x){ return a + x.count; }, 0));

        document.getElementById('audit-logins').textContent  = logins;
        document.getElementById('audit-changes').textContent = changes;
        document.getElementById('audit-deletes').textContent = deletes;

        // Update audit badge on nav
        if (d.total > 0) {
            var badge = document.getElementById('audit-badge');
            badge.textContent = d.total > 999 ? '999+' : d.total;
            badge.style.display = '';
        }
    })
    .catch(function () {});
}

// ── Load actor dropdown ────────────────────────────────────────────────
function loadAuditActors() {
    fetch(API_BASE + '/api/audit/actors', { headers: { Authorization: 'Bearer ' + token } })
    .then(function (r) { return r.json(); })
    .then(function (rows) {
        var sel = document.getElementById('audit-filter-actor');
        sel.innerHTML = '<option value="">All Users</option>';
        rows.forEach(function (r) {
            if (r.actor) sel.innerHTML += '<option value="' + r.actor + '">' + r.actor + '</option>';
        });
    })
    .catch(function () {});
}

// ── Main audit load ────────────────────────────────────────────────────
window.loadAudit = function () {
    auditOffset = 0;
    fetchAuditPage();
};

window.auditPrev = function () {
    var limit = Number(document.getElementById('audit-limit').value);
    auditOffset = Math.max(0, auditOffset - limit);
    fetchAuditPage();
};

window.auditNext = function () {
    var limit = Number(document.getElementById('audit-limit').value);
    if (auditOffset + limit < auditTotal) { auditOffset += limit; fetchAuditPage(); }
};

window.clearAuditFilters = function () {
    document.getElementById('audit-search').value        = '';
    document.getElementById('audit-filter-actor').value  = '';
    document.getElementById('audit-filter-type').value   = '';
    document.getElementById('audit-filter-target').value = '';
    document.getElementById('audit-from').value          = '';
    document.getElementById('audit-to').value            = '';
    auditOffset = 0;
    fetchAuditPage();
};

function fetchAuditPage() {
    var limit  = Number(document.getElementById('audit-limit').value) || 50;
    var search = document.getElementById('audit-search').value.trim();
    var actor  = document.getElementById('audit-filter-actor').value;
    var type   = document.getElementById('audit-filter-type').value;
    var target = document.getElementById('audit-filter-target').value;
    var from   = document.getElementById('audit-from').value;
    var to     = document.getElementById('audit-to').value;

    var params = new URLSearchParams({
        limit:  limit,
        offset: auditOffset
    });
    if (search) params.set('search', search);
    if (actor)  params.set('actor', actor);
    if (type)   params.set('event_type', type);
    if (target) params.set('target_type', target);
    if (from)   params.set('from', from + 'T00:00:00');
    if (to)     params.set('to',   to   + 'T23:59:59');

    document.getElementById('audit-tbody').innerHTML =
        '<tr><td colspan="11" style="text-align:center;padding:24px;color:var(--text3);font-family:var(--mono)">Loading…</td></tr>';

    fetch(API_BASE + '/api/audit?' + params.toString(), {
        headers: { Authorization: 'Bearer ' + token }
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
        auditTotal = d.total;
        renderAuditTable(d.events, d.total, limit);
    })
    .catch(function (err) {
        document.getElementById('audit-tbody').innerHTML =
            '<tr><td colspan="11" style="text-align:center;padding:24px;color:var(--red);font-family:var(--mono)">Failed to load audit data</td></tr>';
    });
}

// ── Render audit table ─────────────────────────────────────────────────
function renderAuditTable(events, total, limit) {
    var tbody = document.getElementById('audit-tbody');
    var label = document.getElementById('audit-count-label');
    var prev  = document.getElementById('audit-prev');
    var next  = document.getElementById('audit-next');
    var pgLbl = document.getElementById('audit-page-label');

    label.textContent = total + ' event' + (total !== 1 ? 's' : '') + ' found';
    prev.disabled     = auditOffset === 0;
    next.disabled     = auditOffset + limit >= total;
    var currentPageNum = Math.floor(auditOffset / limit) + 1;
    var totalPages     = Math.max(1, Math.ceil(total / limit));
    pgLbl.textContent  = 'Page ' + currentPageNum + ' / ' + totalPages;

    if (!events || events.length === 0) {
        tbody.innerHTML = '<tr><td colspan="11" style="text-align:center;padding:32px;color:var(--text3);font-family:var(--mono)">No events found matching filters</td></tr>';
        return;
    }

    var rows = events.map(function (ev, i) {
        var isEven     = i % 2 === 0;
        var evtClass   = getEvtClass(ev.event_type);
        var evtLabel   = formatEventType(ev.event_type);
        var roleClass  = ev.actor_role === 'administrator' ? 'role-admin' : 'role-operator';
        var roleLabel  = ev.actor_role || '—';
        var ts         = formatAuditTS(ev.timestamp);
        var beforeHtml = ev.before_val ? '<div class="json-diff" title="' + escHtml(JSON.stringify(ev.before_val)) + '">' + shortJson(ev.before_val) + '</div>' : '<span style="color:var(--text3)">—</span>';
        var afterHtml  = ev.after_val  ? '<div class="json-diff" title="' + escHtml(JSON.stringify(ev.after_val))  + '">' + shortJson(ev.after_val)  + '</div>' : '<span style="color:var(--text3)">—</span>';
        var targetHtml = ev.target_id  ? '<span class="target-badge"><i class="ph ' + targetIcon(ev.target_type) + '"></i>&nbsp;' + escHtml(ev.target_id) + '</span>' : '<span style="color:var(--text3)">—</span>';
        var statusHtml = (ev.status === 'ok' || !ev.status)
            ? '<span class="status-ok">✓ OK</span>'
            : '<span class="status-fail">✗ ' + escHtml(ev.status) + '</span>';

        return '<tr class="audit-tr' + (isEven ? ' audit-tr-even' : '') + '">'
            + '<td class="audit-td" style="color:var(--text3);font-family:var(--mono);font-size:0.7rem">' + (ev.id || '') + '</td>'
            + '<td class="audit-td" style="white-space:nowrap;font-family:var(--mono);font-size:0.72rem">' + ts + '</td>'
            + '<td class="audit-td" style="font-weight:600">' + escHtml(ev.actor || 'system') + '</td>'
            + '<td class="audit-td"><span class="role-pill ' + roleClass + '">' + roleLabel + '</span></td>'
            + '<td class="audit-td"><span class="evt-badge ' + evtClass + '">' + evtLabel + '</span></td>'
            + '<td class="audit-td">' + targetHtml + '</td>'
            + '<td class="audit-td" style="color:var(--text1);font-size:0.78rem">' + escHtml(ev.detail || '—') + '</td>'
            + '<td class="audit-td">' + beforeHtml + '</td>'
            + '<td class="audit-td">' + afterHtml  + '</td>'
            + '<td class="audit-td" style="font-family:var(--mono);font-size:0.7rem;color:var(--text2)">' + escHtml(ev.ip_address || '—') + '</td>'
            + '<td class="audit-td">' + statusHtml + '</td>'
            + '</tr>';
    }).join('');

    tbody.innerHTML = rows;
}

// ── Audit helpers ──────────────────────────────────────────────────────
function getEvtClass(type) {
    if (!type) return 'evt-system';
    if (type === 'login')   return 'evt-login';
    if (type === 'logout')  return 'evt-logout';
    if (type.startsWith('create') || type === 'seed') return 'evt-create';
    if (type.startsWith('update') || type === 'ack_alert' || type === 'ack_all_alerts') return 'evt-update';
    if (type.startsWith('delete') || type === 'prune' || type === 'clear_readings') return 'evt-delete';
    if (type === 'backup')  return 'evt-system';
    return 'evt-system';
}

function formatEventType(type) {
    if (!type) return '—';
    var labels = {
        login:         '⇢ Login',
        logout:        '⇠ Logout',
        create_device: '+ Device',
        update_device: '✎ Device',
        delete_device: '✕ Device',
        create_user:   '+ User',
        update_user:   '✎ User',
        delete_user:   '✕ User',
        ack_alert:     '✓ Alert',
        ack_all_alerts:'✓ All Alerts',
        backup:        '⎙ Backup',
        prune:         '⊘ Prune',
        clear_readings:'⊘ Readings',
        seed:          '⚙ Seed',
    };
    return labels[type] || type.replace(/_/g,' ');
}

function targetIcon(type) {
    var icons = { device:'ph-cpu', user:'ph-user', session:'ph-key', alert:'ph-warning', database:'ph-database' };
    return icons[type] || 'ph-dot';
}

function formatAuditTS(ts) {
    if (!ts) return '—';
    try {
        var d = new Date(ts.replace(' ', 'T') + (ts.includes('Z') ? '' : 'Z'));
        if (isNaN(d)) return ts;
        return d.toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' })
             + '<br><span style="color:var(--text3)">'
             + d.toLocaleTimeString('en-IN', { hour12:false })
             + '</span>';
    } catch { return ts; }
}

function shortJson(obj) {
    if (!obj) return '—';
    var str = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 1);
    return str.length > 80 ? str.slice(0, 80) + '…' : str;
}

function escHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Export audit CSV ───────────────────────────────────────────────────
window.exportAuditCsv = function () {
    var limit  = 5000; // export up to 5000 rows
    var params = new URLSearchParams({ limit: limit, offset: 0 });
    var search = document.getElementById('audit-search').value.trim();
    var actor  = document.getElementById('audit-filter-actor').value;
    var type   = document.getElementById('audit-filter-type').value;
    var target = document.getElementById('audit-filter-target').value;
    var from   = document.getElementById('audit-from').value;
    var to     = document.getElementById('audit-to').value;
    if (search) params.set('search', search);
    if (actor)  params.set('actor', actor);
    if (type)   params.set('event_type', type);
    if (target) params.set('target_type', target);
    if (from)   params.set('from', from + 'T00:00:00');
    if (to)     params.set('to',   to   + 'T23:59:59');

    fetch(API_BASE + '/api/audit?' + params.toString(), {
        headers: { Authorization: 'Bearer ' + token }
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
        var csv = 'ID,Timestamp,User,Role,Event Type,Target Type,Target ID,Description,Before,After,IP Address,Status\n';
        d.events.forEach(function (ev) {
            csv += [
                ev.id, ev.timestamp, ev.actor, ev.actor_role, ev.event_type,
                ev.target_type, ev.target_id,
                '"' + (ev.detail || '').replace(/"/g,'""') + '"',
                '"' + (ev.before_val ? JSON.stringify(ev.before_val) : '').replace(/"/g,'""') + '"',
                '"' + (ev.after_val  ? JSON.stringify(ev.after_val)  : '').replace(/"/g,'""') + '"',
                ev.ip_address, ev.status
            ].join(',') + '\n';
        });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(new Blob([csv], { type:'text/csv' }));
        a.download = 'nucleosense_audit_' + new Date().toISOString().slice(0,10) + '.csv';
        a.click();
        toast('Audit trail exported (' + d.events.length + ' events)', 'success');
    })
    .catch(function () { toast('Export failed', 'error'); });
};

// ═══════════════════════════════════════════════════════════════════════
// PROFILES — Recipe Programming (multi-device setpoint bundles)
// ═══════════════════════════════════════════════════════════════════════
var profiles = [];
var profileDeviceMap = {};   // device_id -> { name, params:[{param_id,param_label,unit}] }
var editingProfileId = null;
var pendingStartProfileId = null;
var pendingDeleteProfileId = null;

function loadProfiles() {
    fetch(API_BASE + '/api/devices', { headers: { Authorization: 'Bearer ' + token } })
    .then(function (r) { return r.json(); })
    .then(function (devs) {
        profileDeviceMap = {};
        (devs || []).forEach(function (d) {
            profileDeviceMap[d.id] = {
                name: d.name,
                params: (d.setpoints || []).map(function (sp) {
                    return { param_id: sp.param_id, param_label: sp.param_label, unit: sp.unit };
                })
            };
        });
    })
    .catch(function () {})
    .then(function () {
        return fetch(API_BASE + '/api/profiles', { headers: { Authorization: 'Bearer ' + token } });
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
        profiles = Array.isArray(d) ? d : [];
        renderProfileGrid();
    })
    .catch(function () {
        document.getElementById('profiles-grid').innerHTML =
            '<div style="grid-column:1/-1;padding:50px;text-align:center;color:var(--text3)">Could not load profiles — check server connection</div>';
    });
}

function renderProfileGrid() {
    var grid = document.getElementById('profiles-grid');
    var canDelete = currentUser && (currentUser.role === 'administrator' || currentUser.role === 'factory');
    if (!profiles.length) {
        grid.innerHTML = '<div style="grid-column:1/-1;padding:50px;text-align:center;color:var(--text3)">'
            + '<i class="ph ph-flask" style="font-size:2.2rem;display:block;margin:0 auto 10px;opacity:0.3"></i>'
            + 'No profiles yet. Create one to program multiple setpoints at once.</div>';
        return;
    }
    grid.innerHTML = profiles.map(function (p) {
        var deviceCount = new Set((p.items || []).map(function (it) { return it.device_id; })).size;
        var itemsHtml = (p.items || []).slice(0, 4).map(function (it) {
            return '<div style="display:flex;justify-content:space-between;gap:8px;font-size:0.72rem;font-family:var(--mono);color:var(--text2);padding:3px 0;border-bottom:1px solid var(--border)">'
                + '<span>' + escHtml(it.device_id) + ' · ' + escHtml(it.param_label || it.param_id) + '</span>'
                + '<span style="color:var(--accent);white-space:nowrap">' + it.value + ' ' + escHtml(it.unit || '') + '</span></div>';
        }).join('');
        var more = (p.items || []).length > 4 ? '<div style="font-size:0.68rem;color:var(--text3);padding-top:4px">+' + (p.items.length - 4) + ' more…</div>' : '';
        var lastRun = p.last_run ? ('Last run ' + p.last_run.run_at + ' by ' + escHtml(p.last_run.run_by_name || p.last_run.run_by)) : 'Never run';
        var activeBadge = p.is_active
            ? '<div class="nav-badge" style="background:var(--green);color:#04140b;flex-shrink:0">ACTIVE</div>'
            : '<div class="nav-badge" style="flex-shrink:0">' + (p.items || []).length + ' pts</div>';
        return '<div class="stat-card" style="flex-direction:column;align-items:stretch;gap:10px;padding:16px' + (p.is_active ? ';border-color:var(--green)' : '') + '">'
            + '<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px">'
            +   '<div><div style="font-weight:700;font-size:0.92rem">' + escHtml(p.name) + '</div>'
            +   '<div style="font-size:0.74rem;color:var(--text3);margin-top:2px">' + escHtml(p.description || 'No description') + '</div></div>'
            +   activeBadge
            + '</div>'
            + '<div>' + itemsHtml + more + '</div>'
            + '<div style="font-size:0.68rem;color:var(--text3)"><i class="ph ph-clock-counter-clockwise"></i> ' + lastRun + ' · ' + deviceCount + ' device(s)</div>'
            + '<div style="display:flex;gap:6px;margin-top:4px">'
            +   '<button class="btn-submit" style="flex:1;justify-content:center" onclick="openProfileStartModal(' + p.id + ')"><i class="ph ph-play"></i> ' + (p.is_active ? 'Restart' : 'Start') + '</button>'
            +   '<button class="btn-cancel" onclick="openEditProfileModal(' + p.id + ')" title="Edit"><i class="ph ph-pencil-simple"></i></button>'
            +   (canDelete ? '<button class="btn-cancel" style="color:var(--red)" onclick="openDeleteProfileModal(' + p.id + ')" title="Delete"><i class="ph ph-trash"></i></button>' : '')
            + '</div>'
            + '</div>';
    }).join('');
}

// ── Create / Edit modal ─────────────────────────────
window.openNewProfileModal = function () {
    editingProfileId = null;
    document.getElementById('profile-modal-title').textContent = 'New Profile';
    document.getElementById('profile-name').value = '';
    document.getElementById('profile-desc').value = '';
    document.getElementById('profile-modal-err').textContent = '';
    document.getElementById('profile-items-list').innerHTML = '';
    addProfileItemRow();
    document.getElementById('profile-modal').classList.add('open');
};
window.openEditProfileModal = function (id) {
    var p = profiles.find(function (x) { return x.id === id; });
    if (!p) return;
    editingProfileId = id;
    document.getElementById('profile-modal-title').textContent = 'Edit Profile';
    document.getElementById('profile-name').value = p.name;
    document.getElementById('profile-desc').value = p.description || '';
    document.getElementById('profile-modal-err').textContent = '';
    document.getElementById('profile-items-list').innerHTML = '';
    (p.items || []).forEach(function (it) { addProfileItemRow(it); });
    if (!(p.items || []).length) addProfileItemRow();
    document.getElementById('profile-modal').classList.add('open');
};
window.closeProfileModal = function () {
    document.getElementById('profile-modal').classList.remove('open');
    editingProfileId = null;
};

function deviceOptionsHtml(selectedId) {
    var ids = Object.keys(profileDeviceMap);
    if (!ids.length) return '<option value="">No devices available</option>';
    return ids.map(function (id) {
        return '<option value="' + escHtml(id) + '"' + (id === selectedId ? ' selected' : '') + '>' + escHtml(profileDeviceMap[id].name || id) + '</option>';
    }).join('');
}
function paramOptionsHtml(deviceId, selectedParamId) {
    var dev = profileDeviceMap[deviceId];
    var params = dev ? dev.params : [];
    if (!params || !params.length) return '<option value="">No setpoints on this device</option>';
    return params.map(function (pr) {
        return '<option value="' + escHtml(pr.param_id) + '" data-unit="' + escHtml(pr.unit || '') + '" data-label="' + escHtml(pr.param_label || pr.param_id) + '"'
            + (pr.param_id === selectedParamId ? ' selected' : '') + '>' + escHtml(pr.param_label || pr.param_id) + ' (' + escHtml(pr.unit || '—') + ')</option>';
    }).join('');
}
window.addProfileItemRow = function (existing) {
    var list = document.getElementById('profile-items-list');
    var row = document.createElement('div');
    row.className = 'profile-item-row';
    row.style.cssText = 'display:flex;gap:8px;align-items:flex-end;margin-bottom:10px;flex-wrap:wrap';
    var devId = existing ? existing.device_id : Object.keys(profileDeviceMap)[0];
    row.innerHTML =
        '<div class="field-group" style="flex:2;min-width:140px;margin-bottom:0">'
        +   '<label>Device</label>'
        +   '<select class="pi-device" style="width:100%" onchange="onProfileDeviceChange(this)">' + deviceOptionsHtml(devId) + '</select>'
        + '</div>'
        + '<div class="field-group" style="flex:2;min-width:140px;margin-bottom:0">'
        +   '<label>Parameter</label>'
        +   '<select class="pi-param" style="width:100%">' + paramOptionsHtml(devId, existing ? existing.param_id : null) + '</select>'
        + '</div>'
        + '<div class="field-group" style="flex:1;min-width:80px;margin-bottom:0">'
        +   '<label>Value</label>'
        +   '<input class="pi-value" type="number" step="any" value="' + (existing ? existing.value : '') + '"/>'
        + '</div>'
        + '<button class="btn-cancel" style="color:var(--red)" onclick="removeProfileItemRow(this)" title="Remove"><i class="ph ph-trash"></i></button>';
    list.appendChild(row);
};
window.removeProfileItemRow = function (btn) {
    var list = document.getElementById('profile-items-list');
    var row = btn.closest('.profile-item-row');
    if (row) row.remove();
    if (!list.children.length) addProfileItemRow();
};
window.onProfileDeviceChange = function (sel) {
    var row = sel.closest('.profile-item-row');
    var paramSel = row.querySelector('.pi-param');
    paramSel.innerHTML = paramOptionsHtml(sel.value, null);
};

window.saveProfile = function () {
    var name = document.getElementById('profile-name').value.trim();
    var desc = document.getElementById('profile-desc').value.trim();
    var errEl = document.getElementById('profile-modal-err');
    errEl.textContent = '';
    if (!name) { errEl.textContent = 'Profile name required'; return; }

    var items = [];
    var rowErr = null;
    document.querySelectorAll('#profile-items-list .profile-item-row').forEach(function (row) {
        var devSel = row.querySelector('.pi-device');
        var parSel = row.querySelector('.pi-param');
        var valInp = row.querySelector('.pi-value');
        var deviceId = devSel.value;
        var paramId  = parSel.value;
        var opt      = parSel.options[parSel.selectedIndex];
        var value    = valInp.value;
        if (!deviceId || !paramId || value === '') { rowErr = 'Every row needs a device, parameter, and value'; return; }
        items.push({
            device_id: deviceId,
            param_id: paramId,
            param_label: opt ? opt.getAttribute('data-label') : paramId,
            unit: opt ? opt.getAttribute('data-unit') : '',
            value: parseFloat(value)
        });
    });
    if (rowErr) { errEl.textContent = rowErr; return; }
    if (!items.length) { errEl.textContent = 'Add at least one setpoint'; return; }

    var btn = document.getElementById('profile-save-btn');
    btn.disabled = true; btn.textContent = 'Saving…';

    var url = API_BASE + (editingProfileId ? ('/api/profiles/' + editingProfileId) : '/api/profiles');
    var method = editingProfileId ? 'PUT' : 'POST';

    fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
        body: JSON.stringify({ name: name, description: desc, items: items })
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
        btn.disabled = false; btn.innerHTML = '<i class="ph ph-check"></i> Save Profile';
        if (d.error) { errEl.textContent = d.error; return; }
        closeProfileModal();
        toast('Profile "' + name + '" saved', 'success');
        loadProfiles();
    })
    .catch(function () {
        btn.disabled = false; btn.innerHTML = '<i class="ph ph-check"></i> Save Profile';
        errEl.textContent = 'Network error — could not reach server';
    });
};

// ── Start profile (reason + electronic signature) ───────────────────
window.openProfileStartModal = function (id) {
    var p = profiles.find(function (x) { return x.id === id; });
    if (!p) return;
    pendingStartProfileId = id;
    var lines = (p.items || []).map(function (it) {
        return it.device_id + ' / ' + (it.param_label || it.param_id) + ' \u2192 ' + it.value + ' ' + (it.unit || '');
    });
    document.getElementById('profile-start-summary').textContent = 'Profile: ' + p.name + '\n' + lines.join('\n');
    document.getElementById('profile-start-user').value = currentUser ? currentUser.username : '';
    document.getElementById('profile-start-pass').value = '';
    document.getElementById('profile-start-reason').value = '';
    document.getElementById('profile-start-err').textContent = '';
    document.getElementById('profile-start-modal').classList.add('open');
};
window.closeProfileStartModal = function () {
    document.getElementById('profile-start-modal').classList.remove('open');
    pendingStartProfileId = null;
};
window.submitProfileStart = function () {
    if (!pendingStartProfileId) return;
    var reason = document.getElementById('profile-start-reason').value.trim();
    var pw     = document.getElementById('profile-start-pass').value;
    var errEl  = document.getElementById('profile-start-err');
    var btn    = document.getElementById('profile-start-btn');
    errEl.textContent = '';
    if (reason.length < 5) { errEl.textContent = 'Reason must be at least 5 characters (21 CFR §11.10a)'; return; }
    if (!pw) { errEl.textContent = 'Password required for electronic signature (21 CFR §11.50)'; return; }
    btn.textContent = 'Verifying…'; btn.disabled = true;

    fetch(API_BASE + '/api/profiles/' + pendingStartProfileId + '/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
        body: JSON.stringify({ reason: reason, esig_password: pw })
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
        btn.disabled = false; btn.innerHTML = '<i class="ph ph-pen-nib"></i> Sign & Start';
        if (d.ok) {
            var total = d.applied_count + d.failed_count;
            closeProfileStartModal();
            toast('Profile started — ' + d.applied_count + '/' + total + ' setpoint(s) applied', 'success');
            loadProfiles();
            loadActiveProfileBanner();
        } else {
            var code = d.code || '';
            if (code === 'ESIG_REQUIRED') errEl.textContent = 'Electronic signature invalid — wrong password';
            else if (code === 'REASON_REQUIRED') errEl.textContent = 'Reason is required and must be meaningful';
            else errEl.textContent = d.error || 'Server error';
        }
    })
    .catch(function () {
        btn.disabled = false; btn.innerHTML = '<i class="ph ph-pen-nib"></i> Sign & Start';
        errEl.textContent = 'Network error — could not reach server';
    });
};

// ── Delete profile ───────────────────────────────────
window.openDeleteProfileModal = function (id) {
    var p = profiles.find(function (x) { return x.id === id; });
    if (!p) return;
    pendingDeleteProfileId = id;
    document.getElementById('delete-profile-summary').textContent = 'Profile: ' + p.name + ' (' + (p.items || []).length + ' setpoint(s))';
    document.getElementById('delete-profile-reason').value = '';
    document.getElementById('delete-profile-err').textContent = '';
    document.getElementById('delete-profile-modal').classList.add('open');
};
window.closeDeleteProfileModal = function () {
    document.getElementById('delete-profile-modal').classList.remove('open');
    pendingDeleteProfileId = null;
};
window.submitDeleteProfile = function () {
    if (!pendingDeleteProfileId) return;
    var reason = document.getElementById('delete-profile-reason').value.trim();
    var errEl  = document.getElementById('delete-profile-err');
    if (reason.length < 5) { errEl.textContent = 'Reason must be at least 5 characters (21 CFR §11.10a)'; return; }
    fetch(API_BASE + '/api/profiles/' + pendingDeleteProfileId, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token },
        body: JSON.stringify({ reason: reason })
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
        if (d.error) { errEl.textContent = d.error; return; }
        closeDeleteProfileModal();
        toast('Profile deleted', 'success');
        loadProfiles();
    })
    .catch(function () { errEl.textContent = 'Network error — could not reach server'; });
};

}());