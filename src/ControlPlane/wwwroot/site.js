'use strict';
const toggle=document.querySelector('.menu-toggle');
if(toggle)toggle.onclick=()=>{const open=document.querySelector('.site-header').classList.toggle('menu-open');toggle.setAttribute('aria-expanded',String(open));};
fetch('/api/me',{credentials:'same-origin'}).then(r=>r.ok?r.json():null).then(me=>{if(!me)return;const link=document.querySelector('[data-account-link]');if(link){link.href='/console';link.textContent='进入控制台 ↗';}const login=document.querySelector('.login-link');if(login){login.href='/console#security';login.textContent='我的账号';}}).catch(()=>{});
