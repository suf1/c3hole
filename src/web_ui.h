// Embedded dashboard + first-run setup pages (served from flash, no filesystem).
#pragma once
#include <pgmspace.h>

static const char SETUP_PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>C3Hole setup</title>
<style>body{font:16px system-ui;max-width:420px;margin:30px auto;padding:0 14px}input,button{width:100%;padding:10px;margin:6px 0;box-sizing:border-box;font-size:16px}
button{background:#1f6feb;color:#fff;border:0;border-radius:6px}small{color:#666}</style></head><body>
<h2>C3Hole first-time setup</h2>
<p><small>Enter your 2.4&nbsp;GHz Wi-Fi and choose a dashboard password (8+ characters).</small></p>
<form method=post action=/setup>
<input name=ssid placeholder="Wi-Fi name (SSID)" required maxlength=32>
<input name=wpass type=password placeholder="Wi-Fi password" maxlength=63>
<input name=dpass type=password placeholder="Dashboard password (8+ chars)" maxlength=60>
<label><input type=checkbox name=nopw value=1 style="width:auto"> No password (anyone on my network can open the dashboard)</label>
<button>Save and restart</button></form></body></html>)HTML";

static const char DASH_PAGE[] PROGMEM = R"HTML(<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>C3Hole</title>
<style>
:root{--bg:#f4f6f9;--card:#fff;--tx:#1b2430;--mu:#667;--ac:#1f6feb;--bd:#dde3ea;--ok:#1a7f37;--bad:#c62828}
@media(prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171d25;--tx:#e6ebf1;--mu:#8b97a6;--bd:#2a3340;--ok:#3fb950;--bad:#f85149}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px system-ui,sans-serif}
header{padding:14px 18px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--bd)}
h1{font-size:20px;margin:0}main{max-width:980px;margin:0 auto;padding:14px;display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(290px,1fr))}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px}.card h2{font-size:13px;text-transform:uppercase;letter-spacing:.06em;color:var(--mu);margin:0 0 10px}
.big{font-size:30px;font-weight:700}.row{display:flex;justify-content:space-between;gap:8px;padding:3px 0;border-bottom:1px dashed var(--bd)}.row:last-child{border:0}.row span:first-child{color:var(--mu)}
.bar{height:8px;background:var(--bd);border-radius:4px;overflow:hidden;margin:6px 0}.bar i{display:block;height:100%;background:var(--ac)}
input,button,select{font:inherit;padding:8px;border-radius:6px;border:1px solid var(--bd);background:var(--bg);color:var(--tx);width:100%;margin:4px 0}
button{background:var(--ac);color:#fff;border:0;cursor:pointer}button.sec{background:var(--bd);color:var(--tx)}button.dng{background:var(--bad)}
label{font-size:12px;color:var(--mu)}.ok{color:var(--ok)}.bad{color:var(--bad)}ul{margin:0;padding:0;list-style:none;font:13px ui-monospace,monospace}li{padding:2px 0;word-break:break-all}
.wide{grid-column:1/-1}small{color:var(--mu)}progress{width:100%}
</style></head><body>
<header><h1>C3Hole</h1><small id=ver></small></header>
<main>
<div class=card><h2>Queries</h2><div class=big id=total>-</div><div class=bar><i id=pbar style="width:0"></i></div>
<div class=row><span>Blocked</span><b id=blocked>-</b></div><div class=row><span>Blocked share</span><b id=share>-</b></div>
<div class=row><span>Forwarded / answered</span><b id=fwd>-</b></div><div class=row><span>In flight now</span><b id=pend>-</b></div>
<div class=row><span>Timeouts / retries</span><b id=tmo>-</b></div></div>

<div class=card><h2>Blocklist</h2><div class=big id=count>-</div>
<div class=row><span>Status</span><b id=blst>-</b></div><div class=row><span>Built</span><b id=blbuilt>-</b></div>
<div class=row><span>Capacity used</span><b id=blcap>-</b></div><div class=row><span>Flash access</span><b id=blmode>-</b></div>
<div class=row><span>Last update</span><b id=bllast>-</b></div></div>

<div class=card><h2>Bloom filter &amp; lookups</h2>
<div class=row><span>Filter size / hashes</span><b id=bsz>-</b></div><div class=row><span>Estimated false positives</span><b id=bfp>-</b></div>
<div class=row><span>Misses with 0 flash reads</span><b id=bnf>-</b></div><div class=row><span>Binary searches</span><b id=bfs>-</b></div>
<div class=row><span>Free heap (min)</span><b id=heap>-</b></div><div class=row><span>Uptime</span><b id=up>-</b></div>
<div class=row><span>Wi-Fi</span><b id=wifi>-</b></div></div>

<div class=card><h2>System health</h2>
<div class=row><span>Chip temperature</span><b id=temp>-</b></div><div class=row><span>CPU</span><b id=cpu>-</b></div>
<div class=row><span>Last restart reason</span><b id=reset>-</b></div><div class=row><span>Wi-Fi drops (last reason)</span><b id=drops>-</b></div>
<div class=row><span>Largest free block</span><b id=maxblk>-</b></div><div class=row><span>Low-memory events</span><b id=lowheap>-</b></div>
<small>If the dashboard ever disappears, these show why after it comes back (power, crash, Wi-Fi or memory).</small></div>

<div class=card><h2>Recently blocked</h2><ul id=recent></ul></div>
<div class=card><h2>Clients</h2><ul id=clients></ul></div>

<div class=card><h2>Updates</h2><progress id=upb max=100 value=0 hidden></progress><div id=upmsg><small>idle</small></div>
<button onclick="act('/api/fetch','Fetching blocklist...')">Fetch blocklist now</button>
<button class=sec onclick="act('/api/fwfetch','Updating firmware...')">Update firmware from URL</button>
<label>Upload blocklist.bin <small>(replaces the current list)</small></label><input type=file id=blfile accept=.bin>
<button class=sec onclick="upload('blfile','/api/upload/blocklist',true)">Upload blocklist</button>
<label>Upload firmware.bin</label><input type=file id=fwfile accept=.bin>
<button class=sec onclick="upload('fwfile','/api/upload/firmware',false)">Upload firmware</button></div>

<div class=card><h2>Settings</h2>
<label>Blocklist URL (https or http)</label><input id=blurl placeholder="https://.../blocklist.bin">
<label>Auto-update every (hours, 0 = off)</label><input id=blhours type=number min=0 max=8760>
<label>Firmware URL</label><input id=fwurl placeholder="https://.../firmware.bin">
<label>Upstream DNS provider</label><select id=preset onchange=preset()>
<option value=custom>Custom / my own server</option><option value=g>Google 8.8.8.8</option><option value=q9>Quad9 9.9.9.9</option>
<option value=cf>Cloudflare 1.1.1.1</option><option value=ag>AdGuard 94.140.14.14</option><option value=od>OpenDNS 208.67.222.222</option></select>
<label>Upstream 1 / 2 <small>(IPv4, optional :port - e.g. 192.168.0.5:5353 for your own resolver)</small></label>
<input id=up1 oninput="$('preset').value='custom'"><input id=up2 oninput="$('preset').value='custom'" placeholder="optional">
<label>When asking upstream</label><select id=upmode><option value=0>Primary first, secondary if no answer</option><option value=1>Ask both, use the first answer</option></select>
<label>Failover timeout (ms)</label><input id=uptmo type=number min=100 max=5000>
<label>Bloom filter KB (0 = automatic, applied immediately)</label><input id=bloomkb type=number min=0 max=400>
<button onclick=saveCfg()>Save settings</button></div>

<div class=card><h2>Radio &amp; cooling</h2>
<label>Wi-Fi transmit power (lower = cooler, shorter range)</label><select id=txpower>
<option value=8>2 dBm</option><option value=20>5 dBm</option><option value=28>7 dBm</option><option value=34>8.5 dBm</option><option value=44>11 dBm</option>
<option value=52>13 dBm</option><option value=60>15 dBm</option><option value=68>17 dBm</option><option value=74>18.5 dBm</option><option value=76>19 dBm</option><option value=78>19.5 dBm</option></select>
<label>Wi-Fi power save (cooler, slightly slower replies)</label><select id=ps><option value=0>Off - fastest</option><option value=1>Minimum modem sleep</option><option value=2>Maximum modem sleep</option></select>
<label>CPU speed (80 MHz runs cooler; applies after reboot)</label><select id=cpu><option value=160>160 MHz</option><option value=80>80 MHz</option></select>
<button onclick=saveCfg()>Save radio settings</button>
<small>If the chip runs hot or Wi-Fi keeps dropping, try 8.5 dBm first.</small></div>

<div class=card><h2>Security &amp; device</h2>
<div class=row><span>Dashboard password</span><b id=authst>-</b></div>
<label>New dashboard password (8+ chars)</label><input id=newpw type=password autocomplete=new-password>
<button onclick=chpw()>Set password</button>
<button class=sec onclick=nopw()>Remove password (open dashboard)</button>
<label>Wi-Fi network / password</label><input id=wssid placeholder=SSID><input id=wpass type=password placeholder="Wi-Fi password" autocomplete=new-password>
<button class=sec onclick=chwifi()>Save Wi-Fi and reboot</button>
<button class=sec onclick="if(confirm('Reboot now?'))act('/api/reboot','Rebooting...')">Reboot</button>
<button class=dng onclick="if(confirm('Erase ALL settings and return to setup mode?'))act('/api/factory','Resetting...')">Factory reset</button></div>
<div class="card wide"><small id=msg></small></div>
</main>
<script>
const $=id=>document.getElementById(id);let filled=false;
const PRESETS={g:['8.8.8.8','8.8.4.4'],q9:['9.9.9.9','149.112.112.112'],cf:['1.1.1.1','1.0.0.1'],ag:['94.140.14.14','94.140.15.15'],od:['208.67.222.222','208.67.220.220']};
function preset(){const v=$('preset').value;if(PRESETS[v]){$('up1').value=PRESETS[v][0];$('up2').value=PRESETS[v][1]}}
function msg(t,bad){const m=$('msg');m.textContent=t;m.className=bad?'bad':'ok'}
async function api(p,o){o=o||{};o.headers=Object.assign({'X-C3H':'1'},o.headers||{});const r=await fetch(p,o);const t=await r.text();if(!r.ok)throw new Error(t||r.status);try{return JSON.parse(t)}catch(e){return {}}}
async function act(p,m,body){try{msg(m);await api(p,{method:'POST',body:body});msg('Done.')}catch(e){msg(e.message,1)}}
const fmt=n=>Number(n).toLocaleString();
function dur(s){const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return(d?d+'d ':'')+h+'h '+m+'m'}
function when(t){return t?new Date(t*1000).toLocaleString():'never'}
function list(el,items,f){el.textContent='';items.forEach(x=>{const li=document.createElement('li');li.textContent=f(x);el.appendChild(li)});if(!items.length){const li=document.createElement('li');li.textContent='-';el.appendChild(li)}}
async function refresh(){try{const s=await api('/api/status');
$('ver').textContent='v'+s.ver+' - '+s.slot;const d=s.dns,m=s.match,b=s.bloom,l=s.bl,u=s.upd;
$('total').textContent=fmt(d.total);$('blocked').textContent=fmt(d.blocked);
const sh=d.total?100*d.blocked/d.total:0;$('share').textContent=sh.toFixed(1)+'%';$('pbar').style.width=sh+'%';
$('fwd').textContent=fmt(d.forwarded)+' / '+fmt(d.answered);$('pend').textContent=d.pending+' / 32';$('tmo').textContent=d.timeouts+' / '+d.retried;
$('count').textContent=l.valid?fmt(l.count):'no list';$('blst').textContent=l.valid?'active':'EMPTY - fetch or upload a list';$('blst').className=l.valid?'ok':'bad';
$('blbuilt').textContent=l.valid?when(l.created):'-';$('blcap').textContent=l.valid?(100*l.count/l.max).toFixed(0)+'% of '+fmt(l.max):'-';
$('blmode').textContent=l.valid?l.mode:'-';$('bllast').textContent=l.last+(l.lastOk?' ('+when(l.lastOk)+')':'');
$('bsz').textContent=b.on?(b.kb+' KB / k='+b.k):'off (low RAM)';$('bfp').textContent=b.on?(100*b.fpr).toFixed(1)+'%':'-';
$('bnf').textContent=m.misses?(100*m.noflash/m.misses).toFixed(1)+'%':'-';$('bfs').textContent=fmt(m.searches);
$('heap').textContent=Math.round(s.heap.free/1024)+' KB ('+Math.round(s.heap.min/1024)+' KB)';$('up').textContent=dur(s.uptime);
$('wifi').textContent=s.wifi.ssid+' '+s.wifi.rssi+' dBm '+s.wifi.ip;
const y=s.sys;$('temp').textContent=y.temp.toFixed(0)+' C';$('cpu').textContent=y.cpu+' MHz';$('reset').textContent=y.reset;
$('drops').textContent=y.drops+(y.drops?' (reason '+y.disc+')':'');$('maxblk').textContent=Math.round(s.heap.maxblk/1024)+' KB';$('lowheap').textContent=y.lowheap;
$('authst').textContent=s.cfg.noauth?'OFF - open to your network':'on';$('authst').className=s.cfg.noauth?'bad':'ok';
list($('recent'),s.recent,x=>x);list($('clients'),s.clients,c=>c.ip+'  '+fmt(c.total)+' q, '+fmt(c.blocked)+' blocked');
$('upb').hidden=!u.busy;$('upb').value=u.pct;$('upmsg').textContent=u.msg;
if(!filled){const c=s.cfg;for(const k in c)if($(k)&&typeof c[k]!=='boolean')$(k).value=c[k];$('wssid').value=s.wifi.ssid;
for(const k in PRESETS)if(PRESETS[k][0]==c.up1&&PRESETS[k][1]==c.up2)$('preset').value=k;filled=true}
}catch(e){msg(e.message,1)}}
async function saveCfg(){const p=new URLSearchParams();['blurl','blhours','fwurl','up1','up2','bloomkb','txpower','ps','cpu','upmode','uptmo'].forEach(k=>p.append(k,$(k).value));
await act('/api/config','Saving...',p)}
async function chpw(){const v=$('newpw').value;if(v.length<8){msg('Password must be at least 8 characters',1);return}
await act('/api/password','Saving...',new URLSearchParams({pw:v}));msg('Password changed. Your browser will ask for it again.')}
async function nopw(){if(!confirm('Anyone on your network will be able to open this dashboard, change settings and install firmware. Remove the password?'))return;
await act('/api/password','Saving...',new URLSearchParams({nopw:'1'}));filled=false}
async function chwifi(){await act('/api/wifi','Saving...',new URLSearchParams({ssid:$('wssid').value,pass:$('wpass').value}))}
function upload(id,url,isbl){const f=$(id).files[0];if(!f){msg('Choose a file first',1);return}
const go=()=>{const x=new XMLHttpRequest();x.open('POST',url);x.setRequestHeader('X-C3H','1');
x.upload.onprogress=e=>{$('upb').hidden=false;$('upb').value=100*e.loaded/e.total};
x.onload=()=>{$('upb').hidden=true;msg(x.status==200?'Upload complete.':x.responseText,x.status!=200)};
x.onerror=()=>msg('Upload failed',1);const fd=new FormData();fd.append('file',f);x.send(fd)};
if(!isbl){go();return}
const r=new FileReader();r.onload=()=>{const a=new Uint8Array(r.result);const ok=a[0]==0x43&&a[1]==0x33&&a[2]==0x48&&a[3]==0x4c;
if(!ok){msg('Not a C3Hole blocklist (missing C3HL header)',1);return}
if(confirm('This replaces the current blocklist. Continue?'))go()};r.readAsArrayBuffer(f.slice(0,8))}
refresh();setInterval(refresh,3000);
</script></body></html>)HTML";
