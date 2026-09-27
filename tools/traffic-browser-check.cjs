const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright-core');
const {spawn}=require('node:child_process'),fs=require('node:fs'),path=require('node:path'),net=require('node:net'),crypto=require('node:crypto'),assert=require('node:assert/strict');
const delay=ms=>new Promise(r=>setTimeout(r,ms));
const port=()=>new Promise(resolve=>{const s=net.createServer();s.listen(0,'127.0.0.1',()=>{const p=s.address().port;s.close(()=>resolve(p));});});
(async()=>{
 const root=path.resolve(__dirname,'..'),output=path.join(root,'artifacts','traffic-browser',String(Date.now()));fs.mkdirSync(path.join(output,'data'),{recursive:true});
 const web=await port(),vpn=await port(),base='http://127.0.0.1:'+web,secret=()=>crypto.randomBytes(32).toString('base64'),password=secret();
 const days={};for(let i=0;i<30;i++){const date=new Date(Date.now()-i*86400000+8*3600000).toISOString().slice(0,10);days[date]={pageViews:120+i*7,scriptRequests:8+i,downloads:{'edge-vpn-client-linux-arm64-0.3.3.zip':12+i,'edge-vpn-client-linux-x64-0.3.3.zip':7+i%5}};}
 fs.writeFileSync(path.join(output,'data','traffic-statistics.json'),JSON.stringify({schemaVersion:1,startedAt:new Date(Date.now()-30*86400000).toISOString(),historyImported:false,days}));
 const child=spawn('dotnet',[path.join(root,'src/ControlPlane/bin/Release/net10.0/EdgeVpn.ControlPlane.dll')],{cwd:path.join(root,'src/ControlPlane'),windowsHide:true,env:{...process.env,ASPNETCORE_ENVIRONMENT:'Development',ASPNETCORE_URLS:base,PublicUrl:base,DataDirectory:path.join(output,'data'),AdminKey:secret(),PunchNodeKey:secret(),RelayNodeKey:secret(),Coordinator__FirstPort:String(vpn),Coordinator__Capacity:'1',Coordinator__ListenAddress:'127.0.0.1',BootstrapAdmin__Email:'admin@example.com',BootstrapAdmin__Password:password,Logging__LogLevel__Default:'Warning'}});
 child.stdout.pipe(fs.createWriteStream(path.join(output,'server.log')));child.stderr.pipe(fs.createWriteStream(path.join(output,'error.log')));let browser;
 try{
  for(let i=0;i<100;i++){try{if((await fetch(base+'/health')).ok)break;}catch{}await delay(100);}
  browser=await chromium.launch({headless:true,executablePath:process.env.BROWSER_PATH||'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'});
  const context=await browser.newContext({viewport:{width:1440,height:1000}}),page=await context.newPage(),errors=[];page.on('pageerror',err=>errors.push(err.message));page.on('console',msg=>{if(msg.type()==='error')errors.push(msg.text());});
  const login=await context.request.post(base+'/api/login',{headers:{'X-Session-Mode':'cookie'},data:{email:'admin@example.com',password}});assert.equal(login.status(),200);
  await page.goto(base+'/ops');await page.getByRole('heading',{name:'访问与下载统计',exact:true}).waitFor();assert.equal(await page.locator('.traffic-daily-table tbody tr').count(),30);
  await page.screenshot({path:path.join(output,'traffic-desktop.png'),fullPage:true});
  await page.locator('#traffic-range').selectOption('7');await page.waitForFunction(()=>document.querySelectorAll('.traffic-daily-table tbody tr').length===7);
  await page.locator('#traffic-range').selectOption('90');await page.waitForFunction(()=>document.querySelectorAll('.traffic-daily-table tbody tr').length===90);
  await page.getByRole('button',{name:'刷新数据'}).click();await page.locator('#traffic-range').waitFor();assert.equal(await page.locator('#traffic-range').inputValue(),'90');
  await page.setViewportSize({width:390,height:844});await page.screenshot({path:path.join(output,'traffic-mobile.png'),fullPage:true});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,'mobile page must not overflow');
  await page.goto(base+'/ops#accounts');await page.getByRole('heading',{name:'用户与会员',exact:true}).waitFor();await page.goto(base+'/ops#traffic');await page.getByRole('heading',{name:'访问与下载统计',exact:true}).waitFor();
  assert.deepEqual(errors,[]);console.log('PASS: administrator traffic dashboard, 7/30/90 day filters, refresh, route navigation, desktop/mobile and no browser errors.');console.log('Screenshots: '+output);
 }finally{if(browser)await browser.close();child.kill();}
})().catch(e=>{console.error(e);process.exitCode=1;});
