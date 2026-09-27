'use strict';
(async()=>{
 const mode=location.pathname.slice(1),register=mode==='register',recover=mode==='recover';
 const $=id=>document.getElementById(id),form=$('auth-form');
 document.querySelector('.menu-toggle').onclick=e=>{const open=document.querySelector('.site-header').classList.toggle('menu-open');e.currentTarget.setAttribute('aria-expanded',String(open));};
 $('register-tab').classList.toggle('active',register);$('login-tab').classList.toggle('active',!register&&!recover);
 $('auth-title').textContent=register?'创建你的私人网络账号':recover?'恢复你的账号':'欢迎回来';
 $('auth-description').textContent=register?'注册后即可创建网络与设备加入密钥。':recover?'使用你保存的恢复密钥，设置新密码。':'登录后继续管理你的私人网络。';
 $('auth-eyebrow').textContent=register?'START YOUR OWN NETWORK':recover?'ACCOUNT RECOVERY':'WELCOME BACK';
 $('password-label').textContent=recover?'新密码':'密码';$('auth-submit').textContent=register?'注册并创建网络 →':recover?'重置密码 →':'登录控制台 →';
 $('verification-field').hidden=!register;form.verificationCode.required=register;
 $('confirm-field').hidden=!(register||recover);form.confirmPassword.required=register||recover;
 $('recovery-field').hidden=!recover;form.recoveryCode.required=recover;$('recover-link').hidden=register||recover;
 form.password.autocomplete=register||recover?'new-password':'current-password';
 $('toggle-password').onclick=()=>{const show=form.password.type==='password';form.password.type=show?'text':'password';$('toggle-password').textContent=show?'隐藏':'显示';$('toggle-password').setAttribute('aria-label',show?'隐藏密码':'显示密码');};
 let resendUntil=0;
 $('send-code').onclick=async()=>{if(!form.email.reportValidity())return;const b=$('send-code');b.disabled=true;$('form-error').hidden=true;try{const r=await UI.api('/api/auth/email-code','POST',{email:form.email.value.trim()});$('code-note').textContent=r.message;resendUntil=Date.now()+r.retryAfter*1000;const timer=setInterval(()=>{const seconds=Math.ceil((resendUntil-Date.now())/1000);b.textContent=seconds>0?seconds+' 秒后重发':'重新发送';if(seconds<=0){clearInterval(timer);b.disabled=false;}},1000);}catch(error){$('form-error').textContent=error.message;$('form-error').hidden=false;b.disabled=false;}};
 if(register){try{const status=await UI.api('/api/registration');if(!status.mailReady){$('form-error').textContent='平台正在配置注册邮箱服务，注册暂不可用。已有账号可正常登录。';$('form-error').hidden=false;$('auth-submit').disabled=true;$('send-code').disabled=true;}}catch{$('form-error').textContent='无法获取注册服务状态，请刷新页面。';$('form-error').hidden=false;}}
 let recoveryValue='',after='/console';
 $('save-recovery').onclick=()=>UI.download('p2p-vpn-account-recovery.txt','账号：'+form.email.value+'\n恢复密钥：'+recoveryValue+'\n请妥善保存，不要分享。\n');
 $('continue-account').onclick=()=>{recoveryValue='';$('recovery-value').value='';$('recovery-dialog').close();location.assign(after);};
 $('recovery-dialog').addEventListener('cancel',e=>e.preventDefault());
 form.onsubmit=async e=>{e.preventDefault();$('form-error').hidden=true;
  if((register||recover)&&form.password.value!==form.confirmPassword.value){$('form-error').textContent='两次输入的密码不一致。';$('form-error').hidden=false;return;}
  const button=$('auth-submit');button.disabled=true;button.setAttribute('aria-busy','true');
  try{
   const body={email:form.email.value.trim(),password:form.password.value,verificationCode:form.verificationCode.value.trim()};
   const result=recover?await UI.api('/api/auth/recover','POST',{email:body.email,recoveryCode:form.recoveryCode.value.trim(),newPassword:body.password}):await UI.api(register?'/api/register':'/api/login','POST',body);
   if(result.csrfToken)UI.csrf=result.csrfToken;
   if(result.recoveryCode){recoveryValue=result.recoveryCode;$('recovery-value').value=recoveryValue;after=recover?'/login':'/console';$('recovery-dialog').showModal();}
   else location.assign('/console');
  }catch(error){$('form-error').textContent=error.message;$('form-error').hidden=false;}
  finally{button.disabled=false;button.removeAttribute('aria-busy');}
 };
})();
