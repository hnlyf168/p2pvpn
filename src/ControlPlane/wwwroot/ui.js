'use strict';
window.UI={
 csrf:'',
 esc(value){return String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));},
 date(value){return value?new Date(value).toLocaleString('zh-CN',{hour12:false}):'—';},
 async api(url,method='GET',data){const headers={'X-Session-Mode':'cookie'};if(this.csrf)headers['X-CSRF-Token']=this.csrf;if(data!==undefined)headers['Content-Type']='application/json';
  const response=await fetch(url,{method,headers,credentials:'same-origin',body:data===undefined?undefined:JSON.stringify(data)});
  if(!response.ok){const body=await response.json().catch(()=>({}));const error=new Error(body.error||(response.status===429?'操作较频繁，请稍后重试。':'请求未完成，请稍后再试。'));error.status=response.status;throw error;}
  return response.status===204?null:response.json();
 },
 toast(message,error=false){let t=document.getElementById('toast');if(!t)return;t.textContent=message;t.classList.toggle('error',error);t.hidden=false;clearTimeout(this.toastTimer);this.toastTimer=setTimeout(()=>{t.hidden=true;},6500);},
 async busy(button,fn){if(button){button.disabled=true;button.setAttribute('aria-busy','true');}try{return await fn();}catch(e){this.toast(e.message,true);if(e.status===401&&location.pathname.startsWith('/console'))setTimeout(()=>location.assign('/login'),1200);return null;}finally{if(button){button.disabled=false;button.removeAttribute('aria-busy');}}},
 download(name,text,type='text/plain'){const u=URL.createObjectURL(new Blob([text],{type}));const a=document.createElement('a');a.href=u;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),10000);},
 async copy(text){try{await navigator.clipboard.writeText(text);this.toast('已复制。');}catch{this.toast('浏览器未允许剪贴板访问，请手动选中复制。',true);}},
 dialog(title,description,fields,submit='确认',danger=false){
  const d=document.getElementById('action-dialog');d.innerHTML='<form method="dialog" id="modal-form"><p class="eyebrow">P2P VPN CONSOLE</p><h2>'+this.esc(title)+'</h2><p class="modal-hint">'+this.esc(description)+'</p>'+fields+'<div class="form-error" id="modal-error" hidden></div><div class="actions"><button type="button" class="button secondary" id="modal-cancel">取消</button><button class="button '+(danger?'danger':'primary')+'" id="modal-submit">'+this.esc(submit)+'</button></div></form>';
  d.showModal();return new Promise(resolve=>{let done=false;const finish=v=>{if(done)return;done=true;d.close();d.innerHTML='';resolve(v);};d.querySelector('#modal-cancel').onclick=()=>finish(null);d.oncancel=e=>{e.preventDefault();finish(null);};d.querySelector('form').onsubmit=e=>{e.preventDefault();finish(Object.fromEntries(new FormData(e.target)));};});
 },
 async confirm(title,description,button='确认'){return (await this.dialog(title,description,'',button,true))!==null;},
 secret(title,description,text,filename,format='text/plain'){
  const d=document.getElementById('action-dialog');d.innerHTML='<p class="eyebrow">KEEP THIS PRIVATE</p><h2>'+this.esc(title)+'</h2><p>'+this.esc(description)+'</p><textarea rows="5" readonly aria-label="一次性凭据"></textarea><div class="actions"><button class="button secondary" id="secret-copy">复制</button><button class="button secondary" id="secret-save">下载保存</button><button class="button primary" id="secret-close">已保存</button></div>';d.querySelector('textarea').value=text;
  const clear=()=>{d.close();d.innerHTML='';text='';};d.querySelector('#secret-copy').onclick=()=>this.copy(text);d.querySelector('#secret-save').onclick=()=>this.download(filename,text,format);d.querySelector('#secret-close').onclick=clear;d.oncancel=e=>{e.preventDefault();clear();};d.showModal();
 }
};
UI.joinGuide=function(key){
 const d=document.getElementById('action-dialog'),command="curl -fsSL '"+location.origin+"/install.sh' -o edge-vpn-install.sh && sudo sh edge-vpn-install.sh";
 d.innerHTML='<p class="eyebrow">ADD A DEVICE</p><h2>复制加入码，一键安装</h2><p>加入码默认可用 1 次、24 小时内有效。安装过程中粘贴一次即可，不用手动下载和摆放配置文件。</p><label>设备加入码<textarea rows="2" readonly aria-label="设备加入码"></textarea></label><div class="actions"><button class="button secondary small" id="join-copy">复制加入码</button><button class="button secondary small" id="join-save">保存加入码</button></div><div class="install-options"><a class="button primary" href="/install.cmd" download>Windows 一键安装 ↓</a><p class="inline-note">下载后双击，允许管理员权限；按提示粘贴加入码，设备名称可以直接回车。</p><details><summary>Linux 一键安装命令</summary><pre class="node-config" id="linux-command"></pre><button class="button secondary small" id="linux-copy">复制 Linux 命令</button><p class="inline-note">安装时粘贴上方加入码。需要 Linux（x64 / ARM64 / ARM32，静态 musl AOT）、systemd、unzip（或 BusyBox unzip）、curl 与 iproute2。</p></details></div><div class="actions"><a class="link-button" href="/downloads">手动下载安装包</a><button class="button primary small" id="join-close">完成</button></div>';
 d.querySelector('textarea').value=key;d.querySelector('#linux-command').textContent=command;
 d.querySelector('#join-copy').onclick=()=>UI.copy(key);d.querySelector('#join-save').onclick=()=>UI.download('network-join-code.txt',key);d.querySelector('#linux-copy').onclick=()=>UI.copy(command);
 const clear=()=>{key='';d.close();d.innerHTML='';};d.querySelector('#join-close').onclick=clear;d.oncancel=ev=>{ev.preventDefault();clear();};d.showModal();
};
