'use strict';
(() => {
 const settings=window.VEYRO_RUNTIME||{};
 if(!settings.authEnabled)return;
 const apiBase=String(settings.apiBase||'').replace(/\/$/,'');
 const storage='veyro_private_session_v1';
 let token=sessionStorage.getItem(storage)||'';
 let panel,view='login',notice='';
 const auth={
  get token(){return token;},
  logout(){
   const previous=token;token='';sessionStorage.removeItem(storage);
   document.documentElement.classList.add('veyro-auth-pending');
   setView('login','Sessão encerrada.');
   if(previous&&apiBase)fetch(apiBase+'/api/auth/logout',{method:'POST',headers:{Authorization:'Bearer '+previous}}).catch(()=>{});
  }
 };
 window.VEYRO_AUTH=auth;
 async function request(path,method='GET',body){
  if(!apiBase)throw Error('Backend não configurado: prévia visual. Nenhuma senha ou chave foi enviada.');
  let response;
  try{response=await fetch(apiBase+path,{method,mode:'cors',cache:'no-store',headers:{
    'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})
   },body:body?JSON.stringify(body):undefined});}
  catch{throw Error('Não foi possível conectar ao servidor protegido.');}
  const value=await response.json().catch(()=>({}));
  if(!response.ok)throw Error(value.error||('Erro HTTP '+response.status));
  return value;
 }
 function setView(next,message=''){view=next;notice=message;draw();}
 function draw(){
  if(!panel)return;
  panel.hidden=false;
  const registering=view==='register',needsKey=view==='key';
  panel.innerHTML='<div class="veyro-auth-card" role="dialog" aria-modal="true" aria-labelledby="veyro-gate-title">'+
   '<div class="veyro-auth-brand">VEYRO <strong>IA</strong></div>'+
   '<small class="veyro-auth-eyebrow">'+(needsKey?'SEGUNDA ETAPA':'ACESSO PRIVADO')+'</small>'+
   '<h1 id="veyro-gate-title">'+(needsKey?'Configurar OpenAI':registering?'Criar minha conta':'Entrar no Veyro IA')+'</h1>'+
   '<p class="veyro-auth-description">'+(needsKey?'Sua chave será salva criptografada no servidor. Nunca ficará registrada no GitHub.':'Crie um login privado para acessar seu projeto.')+'</p>'+
   '<form id="veyro-auth-form" autocomplete="off">'+
   (needsKey?'<label>Chave secreta da API<input type="password" name="apiKey" placeholder="sk-..." autocomplete="off" spellcheck="false" minlength="20" maxlength="512" required></label>':
    '<label>Usuário<input name="username" placeholder="Seu nome de acesso" pattern="[A-Za-z0-9_.-]+" minlength="3" maxlength="32" autocomplete="username" required></label>'+
    '<label>Senha<input type="password" name="password" placeholder="Mínimo de 12 caracteres" minlength="12" maxlength="128" autocomplete="'+(registering?'new-password':'current-password')+'" required></label>'+
    (registering?'<label>Código privado de instalação<input type="password" name="setupCode" autocomplete="off" required placeholder="Código do servidor"></label>':''))+
   '<button type="submit" class="veyro-auth-main">'+(needsKey?'Salvar chave e entrar':registering?'Criar conta':'Entrar')+'</button></form>'+
   '<p role="status" id="veyro-auth-status"></p>'+
   '<div class="veyro-auth-action"><button type="button" id="veyro-auth-switch">'+(needsKey?'Sair da conta':registering?'Já tenho uma conta':'Criar minha conta')+'</button></div>'+
   '<p class="veyro-auth-footnote">Não envie sua senha nem a chave OpenAI em mensagens ou capturas de tela.</p></div>';
  const feedback=panel.querySelector('#veyro-auth-status');
  feedback.textContent=notice||(!apiBase?'Prévia visual. Falta publicar e configurar o backend.':'');
  panel.querySelector('#veyro-auth-switch').addEventListener('click',()=>needsKey?auth.logout():setView(registering?'login':'register'));
  panel.querySelector('#veyro-auth-form').addEventListener('submit',async event=>{
   event.preventDefault();
   const form=event.currentTarget,button=form.querySelector('button[type=submit]');
   const data=Object.fromEntries(new FormData(form).entries());
   button.disabled=true;feedback.textContent='Conectando...';
   try{
    if(needsKey){await request('/api/key','POST',{apiKey:data.apiKey});form.reset();unlock();}
    else{
     const result=await request(registering?'/api/auth/register':'/api/auth/login','POST',data);
     if(!result.token)throw Error('O servidor não retornou uma sessão.');
     token=result.token;sessionStorage.setItem(storage,token);
     await verify();
    }
   }catch(e){feedback.textContent=e.message||'Erro ao continuar.';button.disabled=false;
    const secret=form.querySelector('input[name=apiKey]');if(secret)secret.value='';
   }
  });
 }
 function unlock(){
  panel.hidden=true;document.documentElement.classList.remove('veyro-auth-pending');
  if(!document.getElementById('veyro-logout')){
   const b=document.createElement('button');b.id='veyro-logout';b.type='button';b.textContent='Sair';
   b.addEventListener('click',auth.logout);
   (document.querySelector('.header')||document.body).appendChild(b);
  }
 }
 async function verify(){
  try{await request('/api/key/status');unlock();}
  catch(e){token='';sessionStorage.removeItem(storage);setView('login',e.message);}
 }
 document.addEventListener('DOMContentLoaded',()=>{
  panel=document.createElement('div');panel.id='veyro-auth-screen';document.body.appendChild(panel);
  draw();if(token)verify();
 },{once:true});
})();