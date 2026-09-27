const fs=require('node:fs'),path=require('node:path');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const root=path.resolve(__dirname,'..'),dir=path.join(root,'docs/wechat');
const bg='#09141f',panel='#102737',stroke='#294455',cyan='#92dfe8',muted='#b0c7d5',white='#f1f7fb',orange='#f2c283';
const start=(w,h)=>`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><style>text{font-family:'Microsoft YaHei','Noto Sans CJK SC',sans-serif}</style><rect width="100%" height="100%" fill="${bg}"/>`;
const text=(x,y,s,size=26,fill=white,anchor='middle')=>`<text x="${x}" y="${y}" font-size="${size}" fill="${fill}" text-anchor="${anchor}">${s}</text>`;
const rect=(x,y,w,h)=>`<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="20" fill="${panel}" stroke="${stroke}" stroke-width="2"/>`;
let steps=start(1000,560)+text(500,72,'让第一次加网，有明确的下一步',40)+text(500,118,'P2P VPN · 从网页引导到设备加入',24,muted);
for(const [i,x,title,a,b] of [[1,40,'注册与验证邮箱','登录自己的控制台','按引导开始创建网络'],[2,360,'创建网络与分组','设置私有网段','需要互通的设备放在同组'],[3,680,'复制命令加设备','每台设备单独生成命令','执行后检查真实在线状态']]){
 steps+=rect(x,170,280,275)+`<circle cx="${x+140}" cy="226" r="27" fill="${cyan}"/>`+text(x+140,236,String(i),28,bg)+text(x+140,303,title,29)+text(x+140,358,a,22,muted)+text(x+140,399,b,20,muted);
}
steps+=text(340,304,'›',34,cyan)+text(660,304,'›',34,cyan)+text(500,512,'一条命令对应一台设备；领取配置成功 ≠ 已经在线',24,cyan)+'</svg>';
let architecture=start(1000,910)+text(500,64,'直连优先，中继独立部署',40);
architecture+=`<defs><marker id="a" markerWidth="9" markerHeight="9" refX="5" refY="3" orient="auto-start-reverse"><path d="M0,0 L6,3 L0,6" fill="none" stroke="${cyan}" stroke-width="1.4"/></marker></defs>`;
architecture+=rect(230,115,540,125)+text(500,166,'公众控制服务',32)+text(500,211,'账号 · 设备认证 · 配置 · 打洞协调',26,muted);
architecture+=`<path d="M340 240 L210 350 M660 240 L790 350" fill="none" stroke="${muted}" stroke-width="2" stroke-dasharray="8 9"/>`;
architecture+=text(175,300,'认证 / 协调',23,muted)+text(825,300,'认证 / 协调',23,muted);
architecture+=rect(60,350,290,120)+rect(650,350,290,120)+text(205,396,'设备 A',32)+text(795,396,'设备 B',32)+text(205,440,'同一网络 · 同一分组',22,muted)+text(795,440,'同一网络 · 同一分组',22,muted);
architecture+=`<path d="M370 414 H630" stroke="${cyan}" stroke-width="4" marker-start="url(#a)" marker-end="url(#a)"/>`+text(500,387,'优先直连',27,cyan);
architecture+=`<path d="M205 470 V644 H320 M795 470 V644 H680" fill="none" stroke="${orange}" stroke-width="3" stroke-dasharray="9 8"/>`;
architecture+=rect(320,565,360,130)+text(500,610,'独立中继节点',32,orange)+text(500,648,'高级会员 · 直连不可用时',24,muted)+text(500,678,'以实际部署并在线为前提',20,muted);
architecture+=rect(60,753,880,110)+text(500,798,'备用打洞节点：提供故障备用协调入口',27)+text(500,838,'主服务与打洞节点均不承担业务数据中转',25,cyan)+'</svg>';
function inline(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\*\*([^*]+)\*\*/g,'<strong style="color:#087782">$1</strong>').replace(/\[([^\]]+)\]\(([^)]+)\)/g,'<a href="$2" style="color:#087782">$1</a>').replace(/^\*([^*]+)\*$/,'<em style="font-size:14px;color:#667781">$1</em>');}
(async()=>{
 fs.mkdirSync(path.join(dir,'design'),{recursive:true});
 const browser=await chromium.launch({headless:true,executablePath:process.env.BROWSER_EXECUTABLE||'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
 try{
  const page=await browser.newPage({viewport:{width:1000,height:1000},deviceScaleFactor:1.5});
  for(const [name,svg] of [['02-steps',steps],['03-architecture',architecture]]){
   fs.writeFileSync(path.join(dir,'design',name+'.svg'),svg);await page.setContent('<html><body style="margin:0">'+svg+'</body></html>');await page.evaluate(()=>document.fonts.ready);await page.locator('svg').screenshot({path:path.join(dir,'images',name+'.png')});
  }
  const md=fs.readFileSync(path.join(dir,'公众号文章.md'),'utf8').replace(/^\uFEFF/,'');let body='',list=false;
  for(const line of md.split(/\r?\n/)){
   if(!line.trim()){if(list){body+='</ul>';list=false;}continue;}
   if(line.startsWith('- ')){if(!list){body+='<ul style="padding-left:24px;margin:18px 0">';list=true;}body+='<li style="margin:8px 0">'+inline(line.slice(2))+'</li>';continue;}
   if(list){body+='</ul>';list=false;}
   const img=line.match(/^!\[([^\]]*)\]\(([^)]+)\)$/);
   if(img){body+=`<figure style="margin:24px 0"><img src="${img[2]}" alt="${img[1]}" style="width:100%;height:auto;display:block;border-radius:10px"/></figure>`;continue;}
   if(line.startsWith('# ')){body+='<h1 style="font-size:30px;line-height:1.5;margin:10px 0 28px">'+inline(line.slice(2))+'</h1>';continue;}
   if(line.startsWith('## ')){body+='<h2 style="font-size:23px;line-height:1.6;border-left:4px solid #087782;padding-left:12px;margin:38px 0 18px">'+inline(line.slice(3))+'</h2>';continue;}
   body+='<p style="margin:18px 0;text-align:justify">'+inline(line)+'</p>';
  }
  const html='<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>公众号文章预览 · P2P VPN</title></head><body style="margin:0;background:#f3f5f6"><article style="max-width:720px;margin:0 auto;background:white;padding:32px 24px;color:#263644;font:17px/1.95 \'Microsoft YaHei\',sans-serif;overflow-wrap:anywhere">'+body+'</article></body></html>';
  fs.writeFileSync(path.join(dir,'预览.html'),html);
  const url=require('node:url').pathToFileURL(path.join(dir,'预览.html')).href;
  await page.setViewportSize({width:390,height:844});await page.goto(url);await page.evaluate(()=>document.fonts.ready);
  const check=await page.evaluate(()=>({images:[...document.images].map(i=>({src:i.getAttribute('src'),loaded:i.complete&&i.naturalWidth>0})),overflow:document.documentElement.scrollWidth>innerWidth}));
  if(check.overflow||check.images.some(i=>!i.loaded))throw Error(JSON.stringify(check));
  fs.mkdirSync(path.join(root,'artifacts/wechat'),{recursive:true});await page.screenshot({path:path.join(root,'artifacts/wechat/mobile-preview.png'),fullPage:true});
  console.log('Rendered two diagrams and article preview. All '+check.images.length+' images loaded; no overflow at 390px.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
