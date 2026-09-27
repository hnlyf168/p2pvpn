'use strict';
const TrafficUI=(()=>{
 const e=UI.esc,n=value=>Number(value).toLocaleString('zh-CN');
 const totals=(label,value,note)=>`<div class="metric-card"><label>${label}</label><strong>${n(value)}</strong><small>${note}</small></div>`;
 function chart(daily){
  const width=900,height=230,left=55,top=18,bottom=190,plot=width-left-15;
  const max=Math.max(1,...daily.flatMap(d=>[d.pageViews,d.downloads])),step=plot/daily.length;
  const marks=[0,.5,1].map(r=>{const y=bottom-(bottom-top)*r;return `<line class="traffic-gridline" x1="${left}" y1="${y}" x2="${width-15}" y2="${y}"/><text class="traffic-axis" x="${left-9}" y="${y+4}" text-anchor="end">${n(Math.round(max*r))}</text>`;}).join('');
  const bars=daily.map((d,i)=>{const x=left+i*step+step*.15,bw=step*.3,pv=(bottom-top)*d.pageViews/max,dl=(bottom-top)*d.downloads/max;
   return `<g><title>${e(d.date)}：访问 ${n(d.pageViews)} 次，安装包下载 ${n(d.downloads)} 次</title><rect class="traffic-pv" x="${x}" y="${bottom-pv}" width="${bw}" height="${pv}" rx="1"/><rect class="traffic-download" x="${x+bw+1}" y="${bottom-dl}" width="${bw}" height="${dl}" rx="1"/></g>`;
  }).join('');
  const every=Math.ceil(daily.length/7);
  const dates=daily.map((d,i)=>i%every===0||i===daily.length-1?`<text class="traffic-axis" x="${left+(i+.5)*step}" y="${bottom+24}" text-anchor="middle">${e(d.date.slice(5))}</text>`:'').join('');
  return `<p class="traffic-mobile-hint">左右滑动可查看完整趋势和表格</p><div class="traffic-chart-scroll"><svg class="traffic-chart" viewBox="0 0 ${width} ${height}" role="img" aria-labelledby="traffic-chart-title traffic-chart-desc"><title id="traffic-chart-title">每日访问与下载趋势</title><desc id="traffic-chart-desc">按北京时间统计；完整数值见下方每日明细表。</desc>${marks}${bars}${dates}</svg></div>`;
 }
 async function render(days){
  const data=await UI.api('/admin/traffic?days='+days);
  const title='访问与下载统计',description='每天有多少访问、多少下载，一眼看清。按北京时间（UTC+8）汇总，仅平台管理员可见。';
  const action='<button class="button secondary small" data-action="refresh">刷新数据</button>';
  const top=`<div class="metric-grid traffic-metrics">${totals('今日访问',data.today.pageViews,'昨日 '+n(data.yesterday.pageViews)+' 次')}${totals('今日安装包下载',data.today.downloads,'昨日 '+n(data.yesterday.downloads)+' 次')}${totals('近 '+days+' 天访问',data.totals.pageViews,'官网页面请求次数（PV）')}${totals('近 '+days+' 天下载',data.totals.downloads,'安装脚本获取 '+n(data.totals.scriptRequests)+' 次')}</div>`;
  const packages=data.packages.map(p=>{const match=p.file.match(/^edge-vpn-(client|control|relay|punch)-(.+)-(\d+\.\d+\.\d+)\.zip$/);const labels={client:'客户端',control:'控制服务',punch:'打洞节点',relay:'中继节点'};return `<tr><td><strong>${match?e(labels[match[1]]):'安装包'}</strong><small class="traffic-filename">${e(p.file)}</small></td><td>${match?e(match[2]):'—'}</td><td>${match?e(match[3]):'—'}</td><td class="traffic-number">${n(p.count)}</td></tr>`;}).join('');
  const body=`<div class="table-toolbar traffic-toolbar"><div><h2>每日趋势</h2><span class="inline-note">${e(data.daily[0].date)} 至 ${e(data.today.date)} · 含今天</span></div><label class="traffic-period">统计范围<select id="traffic-range">${[7,30,90].map(d=>`<option value="${d}" ${d===days?'selected':''}>近 ${d} 天</option>`).join('')}</select></label></div>
   ${!data.persistenceHealthy?'<div class="traffic-warning" role="alert">统计文件暂时无法读写，当前仅显示可用数据；请检查服务器磁盘和数据目录权限。账号和组网服务不受影响。</div>':''}
   <div class="traffic-legend"><span><i class="traffic-pv-dot"></i>官网访问</span><span><i class="traffic-download-dot"></i>安装包下载</span></div>${chart(data.daily)}
   ${data.totals.pageViews===0&&data.totals.downloads===0?'<p class="traffic-empty">这个时间段还没有访问和下载记录。访问官网或获取安装包后，刷新即可查看。</p>':''}
   <details class="panel-content traffic-explanation"><summary>统计口径与数据说明</summary><div><p>访问量：官网页面成功返回的 GET 请求次数，不是独立访客人数；不含后台、控制台、API、健康检查和静态资源。爬虫及自动访问也可能计入。</p><p>下载量：官网安装包成功响应的请求次数，包含在线安装器获取安装包；断点分片仅统计从第 0 字节开始的单段请求。失败、HEAD、304 和续传分片不计入。该数字不代表安装成功或独立下载人数；GitHub 直接下载不在此统计内。</p><p>安装脚本单独计数，避免与安装包混算。仅保存每日汇总，不保存 IP、邮箱、查询参数或安装票据。保留最近 ${n(data.retentionDays)} 天；约每 10 秒落盘，正常重启保留记录，异常断电可能丢失最后一个保存周期。</p><p class="inline-note">${data.historyImported?'已导入现存网站日志；历史范围受日志保留时间限制，旧日志仅统计完整 200 响应，206 分片不回填。':'统计启用前没有记录的日期显示为 0，不代表当时没有访问。'}统计起始：${e(new Intl.DateTimeFormat('zh-CN',{timeZone:'Asia/Shanghai',dateStyle:'medium',timeStyle:'short'}).format(new Date(data.startedAt)))} · 最近保存：${data.lastSavedAt?e(new Intl.DateTimeFormat('zh-CN',{timeZone:'Asia/Shanghai',timeStyle:'medium'}).format(new Date(data.lastSavedAt))):'待保存'}</p></div></details>
   <div class="panel-content traffic-section-heading"><h2>每日明细</h2><p class="inline-note">日期从新到旧排列；脚本获取次数不计入安装包下载。</p></div><div class="table-scroll traffic-daily-table"><table><thead><tr><th>日期（北京时间）</th><th>访问次数</th><th>安装包下载</th><th>安装脚本获取</th></tr></thead><tbody>${[...data.daily].reverse().map(d=>`<tr><td>${e(d.date)}${d.date===data.today.date?' <span class="status-badge">今天</span>':''}</td><td>${n(d.pageViews)}</td><td>${n(d.downloads)}</td><td>${n(d.scriptRequests)}</td></tr>`).join('')}</tbody></table></div>
   <div class="panel-content traffic-section-heading"><h2>安装包下载明细</h2><p class="inline-note">近 ${days} 天，按下载次数排序。</p></div>${packages?`<div class="table-scroll"><table><thead><tr><th>组件 / 文件</th><th>平台</th><th>版本</th><th class="traffic-number">下载次数</th></tr></thead><tbody>${packages}</tbody></table></div>`:'<div class="empty-state"><strong>该时间段暂无安装包下载</strong>客户端和服务端的下载记录会分开显示在这里。</div>'}`;
  return {title,description,action,top,body};
 }
 function alignChart(){const chart=document.querySelector(".traffic-chart-scroll");if(chart)chart.scrollLeft=chart.scrollWidth;}
 window.addEventListener("resize",alignChart);
 return {render,alignChart};
})();
