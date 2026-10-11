'use strict';
const enc = new TextEncoder();
const now = () => Math.floor(Date.now()/1000);
const rnd = n => crypto.getRandomValues(new Uint8Array(n));
const to64 = a => btoa(String.fromCharCode(...a));
const from64 = s => Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const sha = async s => new Uint8Array(await crypto.subtle.digest('SHA-256',enc.encode(s)));
const answer = (x,status=200) => new Response(JSON.stringify(x),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}});
const error = (message,status=400) => answer({error:message},status);
const same = (a,b) => a.length===b.length && a.reduce((v,x,i)=>v|(x^b[i]),0)===0;
// Cloudflare accepts at most 100000 PBKDF2 rounds per invocation.
// Protect the salted hash with a server-only HMAC pepper derived from VEYRO_MASTER_KEY.
async function passwordHash(password,salt,env) {
 if(!env.VEYRO_MASTER_KEY)throw Error('MASTER_KEY_MISSING');
 const pepper=from64(env.VEYRO_MASTER_KEY);
 if(pepper.length!==32)throw Error('MASTER_KEY_LENGTH');
 const hmac=await crypto.subtle.importKey('raw',pepper,{name:'HMAC',hash:'SHA-256'},false,['sign']);
 const keyed=await crypto.subtle.sign('HMAC',hmac,enc.encode(password));
 const k=await crypto.subtle.importKey('raw',keyed,'PBKDF2',false,['deriveBits']);
 return new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations:100000},k,256));
}
async function readBody(request){
 if(Number(request.headers.get('content-length')||0)>24000)throw Error('BODY_LIMIT');
 return request.json();
}
async function getUser(request,env){
 const auth=request.headers.get('authorization')||'';
 if(!/^Bearer [0-9a-f]{64}$/.test(auth))return null;
 const hash=to64(await sha(auth.slice(7)));
 return env.DB.prepare('SELECT u.id,u.username FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').bind(hash,now()).first();
}
async function createSession(env,u){
 const token=Array.from(rnd(32)).map(b=>b.toString(16).padStart(2,'0')).join('');
 await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').bind(to64(await sha(token)),u.id,now()+28800).run();
 return answer({token,username:u.username,expiresIn:28800});
}
async function cipherKey(env){
 if(!env.VEYRO_MASTER_KEY)throw Error('MASTER_KEY_MISSING');
 const key=from64(env.VEYRO_MASTER_KEY);
 if(key.length!==32)throw Error('MASTER_KEY_LENGTH');
 return crypto.subtle.importKey('raw',key,'AES-GCM',false,['encrypt','decrypt']);
}
async function encryptKey(env,id,key){
 const iv=rnd(12);
 const sealed=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:enc.encode(id)},await cipherKey(env),enc.encode(key));
 return {iv:to64(iv),sealed:to64(new Uint8Array(sealed))};
}
async function decryptKey(env,id,row){
 const raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:from64(row.iv),additionalData:enc.encode(id)},await cipherKey(env),from64(row.sealed));
 return new TextDecoder().decode(raw);
}
const OWNER_SETUP_HTML="<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"referrer\" content=\"no-referrer\"><title>Veyro IA | Login de teste</title>\n<style nonce=\"__NONCE__\">\n:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#0b1120;color:#eef2fb}*{box-sizing:border-box}\nbody{margin:0;min-height:100vh;display:grid;place-items:center;padding:18px}\nmain{background:#172039;border:1px solid #455274;border-radius:17px;width:min(450px,100%);padding:25px}\nh1{font-size:28px;margin:5px 0}h1 span{color:#e6c077}p{line-height:1.5;color:#c1cce0}\nsmall{color:#e6c077;letter-spacing:1px;font-weight:600}label{display:block;margin:15px 0;font-size:14px;font-weight:600}\ninput{display:block;width:100%;margin-top:7px;background:#0c1528;color:white;border:1px solid #7c8aa3;border-radius:8px;padding:13px;font:inherit}\nbutton{padding:12px 13px;border:0;border-radius:8px;font:inherit;cursor:pointer}\n.tabs{display:flex;gap:9px;margin-top:22px}.tabs button{flex:1;background:#293652;color:#fff}.tabs button.selected{background:#d9b675;color:#20202a;font-weight:700}\n#submit{width:100%;background:#d9b675;font-weight:700;margin:8px 0;color:#1e1f25}button:disabled{opacity:.5;cursor:wait}\n#msg{color:#ffdc9b;min-height:24px;font-size:14px;white-space:pre-wrap}\n#ok{background:#18352f;border:1px solid #477e65;border-radius:11px;padding:12px}\nfooter{font-size:12px;color:#bbc7d9;line-height:1.55}\n</style></head><body><main><small>TESTE PRIVADO · CLOUDFLARE</small><h1>VEYRO <span>IA</span></h1>\n<p>Crie sua primeira conta ou teste seu login. O site oficial permanece separado.</p>\n<section id=\"gate\"><div class=\"tabs\"><button id=\"register\" class=\"selected\" type=\"button\">Criar conta</button><button id=\"login\" type=\"button\">Entrar</button></div>\n<form id=\"form\" autocomplete=\"off\">\n<label>Usuário<input name=\"username\" required minlength=\"3\" maxlength=\"32\" pattern=\"[A-Za-z0-9_.-]+\" autocomplete=\"username\" spellcheck=\"false\"></label>\n<label>Senha (mínimo de 12 caracteres)<input name=\"password\" type=\"password\" required minlength=\"12\" maxlength=\"128\" autocomplete=\"new-password\"></label>\n<label id=\"codeRow\">Código privado de instalação<input name=\"setupCode\" type=\"password\" required minlength=\"20\" maxlength=\"200\" autocomplete=\"off\" spellcheck=\"false\"></label>\n<button type=\"submit\" id=\"submit\">Criar minha conta</button>\n</form></section><section id=\"ok\" hidden><strong>Conta autenticada ✅</strong><p id=\"who\"></p><p id=\"keystate\"></p><button type=\"button\" id=\"logout\">Sair</button></section>\n<p id=\"msg\" role=\"status\" aria-live=\"polite\"></p>\n<footer>Não envie senhas nem códigos por chat ou fotos. Esta tela testa somente cadastro e login. Não coloque aqui sua chave OpenAI.</footer>\n</main><script nonce=\"__NONCE__\">\n(function(){\n'use strict';\nvar mode='register',storage='veyro_owner_test_session',token=sessionStorage.getItem(storage)||'';\nvar el=function(id){return document.getElementById(id);};\nfunction notice(s){el('msg').textContent=s;}\nfunction setMode(s){mode=s;el('register').classList.toggle('selected',s==='register');el('login').classList.toggle('selected',s==='login');el('codeRow').hidden=s!=='register';el('codeRow').querySelector('input').required=s==='register';el('submit').textContent=s==='register'?'Criar minha conta':'Entrar';el('form').elements.password.autocomplete=s==='register'?'new-password':'current-password';el('form').reset();notice('');}\nasync function call(path,method,body,auth){\nvar h={'Content-Type':'application/json'};if(auth)h.Authorization='Bearer '+auth;\nvar r=await fetch(path,{method:method,headers:h,cache:'no-store',credentials:'omit',body:body?JSON.stringify(body):undefined});\nvar x=await r.json().catch(function(){return {};});if(!r.ok)throw Error(x.error||('Erro HTTP '+r.status));return x;\n}\nasync function verify(){\nvar status=await call('/api/key/status','GET',null,token);\nel('gate').hidden=true;el('ok').hidden=false;el('who').textContent='Usuário: '+status.username;\nel('keystate').textContent=status.configured?'A chave OpenAI já está configurada.':'A chave OpenAI ainda não está configurada. Isso é normal neste teste.';\nnotice('Autenticação e sessão verificadas com sucesso.');\n}\nel('register').onclick=function(){setMode('register');};el('login').onclick=function(){setMode('login');};\nel('form').addEventListener('submit',async function(e){\ne.preventDefault();var btn=el('submit');btn.disabled=true;notice('Conectando...');\ntry{var f=new FormData(e.currentTarget);var data={username:String(f.get('username')||''),password:String(f.get('password')||'')};\nif(mode==='register')data.setupCode=String(f.get('setupCode')||'');\nvar x=await call(mode==='register'?'/api/auth/register':'/api/auth/login','POST',data);\nif(!x.token)throw Error('Resposta sem token de sessão.');\ntoken=x.token;sessionStorage.setItem(storage,token);el('form').reset();await verify();\n}catch(e){notice(e.message||'Erro na autenticação.');}finally{btn.disabled=false;}\n});\nel('logout').onclick=async function(){var old=token;token='';sessionStorage.removeItem(storage);el('ok').hidden=true;el('gate').hidden=false;setMode('login');try{if(old)await call('/api/auth/logout','POST',null,old);}catch(e){}notice('Sessão encerrada.');};\nif(token)verify().catch(function(){token='';sessionStorage.removeItem(storage);setMode('login');notice('Sessão expirada. Entre novamente.');});\n})();\n</script></body></html>";
function ownerSetupPage(){
 const nonce=to64(rnd(16));
 return new Response(OWNER_SETUP_HTML.replaceAll('__NONCE__',nonce),{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store','Content-Security-Policy':"default-src 'none'; connect-src 'self'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"}});
}
async function route(request,env) {
 const path=new URL(request.url).pathname, method=request.method;
 if(!env.DB)return error('Banco D1 indisponível.',503);
 if(method==='GET'&&path==='/setup')return ownerSetupPage();
 if(method==='POST'&&path==='/api/auth/register'){
  if(!env.VEYRO_SETUP_CODE||env.VEYRO_SETUP_CODE.length<20)return error('Código de instalação não configurado.',503);
  const x=await readBody(request),username=String(x.username||'').trim().toLowerCase(),password=String(x.password||''),code=String(x.setupCode||'');
  if(!/^[a-z0-9_.-]{3,32}$/.test(username)||password.length<12||password.length>128)return error('Use um nome válido e senha com pelo menos 12 caracteres.');
  if(code!==env.VEYRO_SETUP_CODE)return error('Código privado de instalação inválido.',403);
  const count=await env.DB.prepare('SELECT COUNT(*) AS n FROM users').first();
  if(count.n!==0)return error('O cadastro inicial já foi realizado.',403);
  const id=crypto.randomUUID(),salt=rnd(16),hash=await passwordHash(password,salt,env);
  try {await env.DB.prepare('INSERT INTO users(id,username,salt,pass_hash,failures,locked_until) VALUES(?,?,?,?,0,0)').bind(id,username,to64(salt),to64(hash)).run();}
  catch{return error('Não foi possível registrar a conta.',409);}
  return createSession(env,{id,username});
 }
 if(method==='POST'&&path==='/api/auth/login'){
  const x=await readBody(request),username=String(x.username||'').trim().toLowerCase(),password=String(x.password||'');
  if(!/^[a-z0-9_.-]{3,32}$/.test(username)||password.length>128)return error('Usuário ou senha incorretos.',401);
  const row=await env.DB.prepare('SELECT * FROM users WHERE username=?').bind(username).first();
  if(!row)return error('Usuário ou senha incorretos.',401);
  if(row.locked_until>now())return error('Aguarde 15 minutos para tentar novamente.',429);
  const match=same(await passwordHash(password,from64(row.salt),env),from64(row.pass_hash));
  if(!match){
   const attempts=row.failures+1;
   await env.DB.prepare('UPDATE users SET failures=?,locked_until=? WHERE id=?').bind(attempts>=5?0:attempts,attempts>=5?now()+900:0,row.id).run();
   return error('Usuário ou senha incorretos.',401);
  }
  await env.DB.prepare('UPDATE users SET failures=0,locked_until=0 WHERE id=?').bind(row.id).run();
  return createSession(env,row);
 }
 const user=await getUser(request,env);
 if(!user)return error('Entre com sua conta para continuar.',401);
 if(path==='/api/auth/logout'&&method==='POST'){
  const token=request.headers.get('authorization').slice(7);
  await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(to64(await sha(token))).run();
  return answer({ok:true});
 }
 if(path==='/api/key/status'&&method==='GET'){
  const row=await env.DB.prepare('SELECT user_id FROM credentials WHERE user_id=?').bind(user.id).first();
  return answer({configured:!!row,username:user.username});
 }
 if(path==='/api/key'&&method==='POST'){
  const body=await readBody(request),apiKey=String(body.apiKey||'').trim();
  if(!/^sk-[A-Za-z0-9_-]{20,}$/.test(apiKey)||apiKey.length>512)return error('Chave da OpenAI inválida.');
  const sealed=await encryptKey(env,user.id,apiKey);
  await env.DB.prepare('INSERT INTO credentials(user_id,iv,sealed) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET iv=excluded.iv,sealed=excluded.sealed').bind(user.id,sealed.iv,sealed.sealed).run();
  return answer({ok:true});
 }
 if(path==='/api/key'&&method==='DELETE'){
  await env.DB.prepare('DELETE FROM credentials WHERE user_id=?').bind(user.id).run();
  return answer({ok:true});
 }
 if(path==='/api/health'&&method==='GET'){
  const row=await env.DB.prepare('SELECT user_id FROM credentials WHERE user_id=?').bind(user.id).first();
  return answer({modelConfigured:!!row,model:env.OPENAI_MODEL||'gpt-4.1-mini'});
 }
 if(path==='/api/chat'&&method==='POST'){
  const row=await env.DB.prepare('SELECT iv,sealed FROM credentials WHERE user_id=?').bind(user.id).first();
  if(!row)return error('Cadastre a chave da API antes de usar o chat.',403);
  const minute=Math.floor(now()/60);
  await env.DB.prepare('INSERT INTO rate_limits(user_id,minute,count) VALUES(?,?,1) ON CONFLICT(user_id,minute) DO UPDATE SET count=count+1').bind(user.id,minute).run();
  const limit=await env.DB.prepare('SELECT count FROM rate_limits WHERE user_id=? AND minute=?').bind(user.id,minute).first();
  if(limit.count>10)return error('Limite de dez mensagens por minuto atingido.',429);
  const payload=await readBody(request),message=String(payload.message||'').trim();
  if(!message||message.length>4000)return error('Digite até 4000 caracteres por mensagem.');
  const history=(Array.isArray(payload.recentMessages)?payload.recentMessages:[]).slice(-10)
   .filter(x=>x&&['user','assistant'].includes(x.role)&&typeof x.content==='string')
   .map(x=>({role:x.role,content:x.content.slice(0,3000)}));
  if(history.at(-1)?.role==='user'&&history.at(-1).content===message)history.pop();
  const apiKey=await decryptKey(env,user.id,row);
  const res=await fetch('https://api.openai.com/v1/chat/completions',{
   method:'POST',headers:{Authorization:'Bearer '+apiKey,'Content-Type':'application/json'},
   body:JSON.stringify({model:env.OPENAI_MODEL||'gpt-4.1-mini',messages:[{role:'system',content:'Responda sempre em português brasileiro com precisão.'},...history,{role:'user',content:message}],stream:true,max_completion_tokens:1000})
  });
  if(!res.ok||!res.body)return error('A OpenAI não respondeu. Confira sua chave, créditos e modelo disponível.',502);
  const reader=res.body.getReader(),decoder=new TextDecoder(),encoder=new TextEncoder();
  const stream=new ReadableStream({async start(c){
   let buff='',done=false;
   function emit(name,value){c.enqueue(encoder.encode('event: '+name+'\ndata: '+JSON.stringify(value)+'\n\n'));}
   try{
    while(true){
     const part=await reader.read();if(part.done)break;buff+=decoder.decode(part.value,{stream:true}).replace(/\r/g,'');
     let pos;
     while((pos=buff.indexOf('\n\n'))>=0){
      const frame=buff.slice(0,pos);buff=buff.slice(pos+2);
      for(const line of frame.split('\n')){
       if(!line.startsWith('data: '))continue;
       const content=line.slice(6).trim();
       if(content==='[DONE]'){done=true;emit('done',{});continue;}
       try{const chunk=JSON.parse(content).choices?.[0]?.delta?.content;if(typeof chunk==='string'&&chunk)emit('token',{text:chunk});}catch{}
      }
     }
    }
    if(!done)emit('done',{});
   }catch{emit('error',{message:'Falha ao continuar a resposta.'});}
   finally{reader.releaseLock();c.close();}
  },cancel(){reader.cancel().catch(()=>{});}});
  return new Response(stream,{headers:{'Content-Type':'text/event-stream; charset=utf-8','Cache-Control':'no-store'}});
 }
 return error('Rota desconhecida.',404);
}
export default {async fetch(request,env){
 const origin=request.headers.get('origin'),allowed=String(env.VEYRO_ALLOWED_ORIGIN||'').replace(/\/$/,''),ownOrigin=new URL(request.url).origin;
 const responseOrigin=origin===ownOrigin?ownOrigin:allowed;
 if(!allowed)return error('Domínio autorizado não configurado.',503);
 if(origin&&origin!==allowed&&origin!==ownOrigin)return error('Origem não autorizada.',403);
 if(request.method==='OPTIONS')return new Response(null,{status:204,headers:{
  'Access-Control-Allow-Origin':responseOrigin,'Access-Control-Allow-Methods':'GET,POST,DELETE,OPTIONS',
  'Access-Control-Allow-Headers':'Authorization,Content-Type','Access-Control-Max-Age':'600','Vary':'Origin'
 }});
 let response;try{response=await route(request,env);}catch(e){
  console.error('VEYRO_AUTH_RUNTIME_FAILURE', {name:e?.name||'Error',path:new URL(request.url).pathname});
  response=error('Erro interno de configuração ou processamento.',500);
 }
 const h=new Headers(response.headers);
 h.set('Access-Control-Allow-Origin',responseOrigin);h.set('Vary','Origin');
 h.set('X-Frame-Options','DENY');h.set('Referrer-Policy','no-referrer');
 h.set('Cache-Control','no-store');h.set('X-Content-Type-Options','nosniff');
 return new Response(response.body,{status:response.status,headers:h});
}};