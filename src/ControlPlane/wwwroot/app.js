'use strict';
let token = sessionStorage.getItem('edge-token') || '', registering = false, networks = [], selected = '';
const $ = (id) => document.getElementById(id);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function notice(message, error = false) { $('notice').textContent = message; $('notice').className = error ? 'error' : ''; $('notice').hidden = false; }
async function api(path, method = 'GET', data) {
  const headers = token ? {Authorization: 'Bearer ' + token} : {};
  if (data !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, {method, headers, body: data === undefined ? undefined : JSON.stringify(data)});
  if (!res.ok) { const body = await res.json().catch(() => ({})); throw new Error(body.error || (res.status === 429 ? '操作过于频繁，请稍后重试。' : '请求失败：' + res.status)); }
  return res.status === 204 ? null : res.json();
}
async function action(button, fn) { if (button) button.disabled = true; try { await fn(); } catch (e) { notice(e.message, true); } finally { if (button) button.disabled = false; } }
function downloadJson(data) { const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], {type:'application/json'})); const a = document.createElement('a'); a.href = url; a.download = 'client.json'; a.click(); setTimeout(() => URL.revokeObjectURL(url), 10000); }
$('auth-switch').onclick = () => { registering = !registering; $('auth-title').textContent = registering ? '注册你的账号' : '登录控制台'; $('auth-submit').textContent = registering ? '注册并进入' : '登录'; $('auth-switch').textContent = registering ? '已有账号？直接登录' : '没有账号？注册一个'; $('auth-form').password.autocomplete = registering ? 'new-password' : 'current-password'; };
$('auth-form').onsubmit = e => { e.preventDefault(); action($('auth-submit'), async () => { const data = Object.fromEntries(new FormData(e.target)); const result = await api(registering ? '/api/register' : '/api/login', 'POST', data); token = result.token; sessionStorage.setItem('edge-token', token); await refresh(); notice('已进入你的网络控制台。'); }); };
$('logout').onclick = () => action($('logout'), async () => { await api('/api/logout', 'POST'); token = ''; sessionStorage.removeItem('edge-token'); networks = []; selected = ''; await refresh(); });
$('network-form').onsubmit = e => { e.preventDefault(); action(e.submitter, async () => { const result = await api('/api/networks', 'POST', Object.fromEntries(new FormData(e.target))); selected = result.id; e.target.reset(); await refresh(); notice('网络已创建，现在可以生成加入密钥。'); }); };
$('join-form').onsubmit = e => { e.preventDefault(); action(e.submitter, async () => { const result = await api('/api/enroll','POST',Object.fromEntries(new FormData(e.target))); downloadJson(result); e.target.reset(); if (token) await refresh(); notice('配置已下载。请将 client.json 放入客户端目录。'); }); };
$('close-dialog').onclick = () => { $('new-key').value = ''; $('key-dialog').close(); };
$('key-dialog').addEventListener('close', () => { $('new-key').value = ''; });
$('copy-key').onclick = () => action($('copy-key'), async () => { await navigator.clipboard.writeText($('new-key').value); notice('密钥已复制。'); });
async function refresh() {
  $('auth').hidden = !!token; $('workspace').hidden = !token; $('logout').hidden = !token;
  if (!token) { $('identity').textContent = '尚未登录'; return; }
  const me = await api('/api/me'); $('identity').textContent = me.email; $('plan').textContent = me.plan === 'pro' ? '高级会员' : '普通会员';
  $('plan-info').textContent = (me.limits.relayEnabled ? '已开通独立中转兜底，设备优先尝试直连。' : '当前套餐提供认证和打洞。打洞失败时不会经过主服务器中转。') +
    ' 网络上限 ' + me.limits.maxNetworks + '，每个网络设备上限 ' + me.limits.maxDevices + (me.planExpiresAt ? '。套餐到期：' + new Date(me.planExpiresAt).toLocaleString() : '。');
  networks = await api('/api/networks'); if (!networks.some(n => n.id === selected)) selected = networks[0]?.id || '';
  $('network-list').innerHTML = networks.length ? networks.map(n => '<button class="network ' + (n.id === selected ? 'active' : '') + '" data-select="' + esc(n.id) + '">' + esc(n.name) + '<small>' + n.groups.length + ' 个分组 · ' + n.devices.filter(d => !d.revoked).length + ' 台设备</small></button>').join('') : '<p class="muted">还没有网络。</p>';
  $('network-list').querySelectorAll('[data-select]').forEach(b => b.onclick = () => { selected = b.dataset.select; refresh().catch(e => notice(e.message,true)); });
  renderDetail();
}
function renderDetail() {
  const n = networks.find(n => n.id === selected); if (!n) { $('network-detail').innerHTML = '<div class="empty">创建第一个网络，开始连接你的设备。</div>'; return; }
  const groupName = id => n.groups.find(g => g.id === id)?.name || '已删除';
  $('network-detail').innerHTML = '<div class="heading"><div><h2>' + esc(n.name) + '</h2><small class="muted">' + esc(n.id) + '</small></div><button class="danger" data-action="delete-network">删除网络</button></div>' +
  '<h3>分组</h3><p class="muted">同一分组内设备互通，不同分组相互隔离。</p><div class="actions">' + n.groups.map(g => '<span class="pill">' + esc(g.name) + '</span>').join('') + '</div>' +
  '<form id="group-form" class="inline-form section-border"><label>新增分组<input name="name" required maxlength="64" placeholder="例如：家庭 / 办公室"></label><button>添加分组</button></form>' +
  '<h3 class="section-border">加入密钥</h3><form id="key-form" class="inline-form"><label>名称<input name="name" required maxlength="64" placeholder="设备邀请"></label><label>分组<select name="groupId">' + n.groups.map(g => '<option value="' + esc(g.id) + '">' + esc(g.name) + '</option>').join('') + '</select></label><label>使用次数<input name="uses" type="number" min="1" max="100" value="1" required></label><label>有效小时<input name="validHours" type="number" min="1" max="720" value="24" required></label><button class="primary">生成密钥</button></form>' +
  '<div class="table-wrap"><table><thead><tr><th>名称 / 分组</th><th>剩余次数</th><th>到期时间</th><th></th></tr></thead><tbody>' + n.keys.map(k => '<tr><td>' + esc(k.name) + ' / ' + esc(groupName(k.groupId)) + '</td><td>' + (k.revoked ? '已吊销' : k.remainingUses) + '</td><td>' + esc(new Date(k.expiresAt).toLocaleString()) + '</td><td>' + (!k.revoked ? '<button data-key="' + esc(k.id) + '">吊销</button>' : '') + '</td></tr>').join('') + '</tbody></table></div>' +
  '<h3>已加入的设备</h3><div class="table-wrap"><table><thead><tr><th>设备</th><th>分组</th><th>虚拟 IP</th><th>授权</th><th></th></tr></thead><tbody>' + n.devices.map(d => '<tr><td>' + esc(d.name) + '</td><td>' + esc(groupName(d.groupId)) + '</td><td>' + esc(d.address) + '</td><td>' + (d.revoked ? '已吊销' : '已授权') + '</td><td>' + (!d.revoked ? '<button data-device="' + esc(d.id) + '" class="danger">移除</button>' : '') + '</td></tr>').join('') + '</tbody></table></div>' +
  (!n.devices.length ? '<p class="muted">还没有设备。生成加入密钥，在下方下载设备配置。</p>' : '') +
  '<button data-action="rotate">轮换网络通信密钥</button><p class="muted">已授权设备会自动更新密钥并重连。加入密钥的吊销不会移除已经加入的设备。</p>';
  $('group-form').onsubmit = e => { e.preventDefault(); action(e.submitter, async () => { await api('/api/networks/' + n.id + '/groups','POST',Object.fromEntries(new FormData(e.target))); await refresh(); }); };
  $('key-form').onsubmit = e => { e.preventDefault(); action(e.submitter, async () => { const data = Object.fromEntries(new FormData(e.target)); data.uses = Number(data.uses); data.validHours = Number(data.validHours); const result = await api('/api/networks/' + n.id + '/keys','POST',data); await refresh(); $('new-key').value = result.key; $('key-dialog').showModal(); }); };
  $('network-detail').querySelectorAll('[data-key]').forEach(b => b.onclick = () => action(b, async () => { await api('/api/networks/' + n.id + '/keys/' + b.dataset.key,'DELETE'); await refresh(); }));
  $('network-detail').querySelectorAll('[data-device]').forEach(b => b.onclick = () => { if (confirm('移除这台设备？其 VPN 访问权限将被吊销。')) action(b, async () => { await api('/api/networks/' + n.id + '/devices/' + b.dataset.device,'DELETE'); await refresh(); }); });
  $('network-detail').querySelector('[data-action="delete-network"]').onclick = e => { if (confirm('删除整个网络及所有设备和加入密钥？此操作无法撤销。')) action(e.target, async () => { await api('/api/networks/' + n.id,'DELETE'); await refresh(); }); };
  $('network-detail').querySelector('[data-action="rotate"]').onclick = e => { if (confirm('轮换通信密钥会短暂断开设备，继续？')) action(e.target, async () => { await api('/api/networks/' + n.id + '/rotate','POST'); notice('密钥已轮换，已授权设备将自动更新。'); }); };
}
api('/api/downloads').then(items => { $('download-list').innerHTML = items.length ? items.map(i => '<a class="download" href="' + esc(i.url) + '">' + esc(i.name) + ' · ' + (i.size/1048576).toFixed(1) + ' MB ↓</a>').join('') : '<p class="muted">管理员尚未上传客户端发布包。</p>'; }).catch(e => notice(e.message,true));
refresh().catch(e => { token = ''; sessionStorage.removeItem('edge-token'); refresh(); notice(e.message,true); });
