'use strict';
(()=>{
  const cfg=window.VEYRO_RUNTIME||{};
  const localFetch=window.fetch.bind(window); // backend local do chrome-demo.js
  const API=String(cfg.apiBase||'').replace(/\/$/,'');
  const LIVE=cfg.useLiveChat===true;
  const DB_KEY='veyro_chrome_test_v010';
  const ACCESS_KEY=cfg.accessCodeStorageKey||'veyro_test_access_code_v020';
  const active=new Map();
  const enc=new TextEncoder();

  function banner(text,ok=false){
    const el=document.getElementById('chrome-demo-banner');
    if(!el)return;
    el.textContent=text;
    el.style.color=ok?'#baf7c5':'#ffd600';
    el.style.borderColor=ok?'#2d6b39':'#665500';
    el.style.background=ok?'#071c0c':'#171300';
  }
  function loadDb(){try{return JSON.parse(localStorage.getItem(DB_KEY)||'null');}catch{return null;}}
  function saveDb(db){try{localStorage.setItem(DB_KEY,JSON.stringify(db));}catch{}}
  function conversation(db,id){return db?.conversations?.find(c=>c.id===id&&!c.deleted);}
  function memFor(db,c){return (db?.memories||[]).filter(m=>m.scope==='user'||m.scope==='system'||(m.scope==='project'&&m.project_id===c.project_id)||(m.scope==='conversation'&&m.conversation_id===c.id)).slice(-30).map(m=>({scope:m.scope,text:String(m.text||'').slice(0,2000)}));}
  function projectFor(db,c){const p=(db?.projects||[]).find(p=>p.id===c.project_id);if(!p)return null;return {title:p.title,state:p.state};}
  function updateAssistant(db,c,requestId,patch){const a=c.messages.find(m=>m.id===requestId);if(!a)return;Object.assign(a,patch,{updated_at:Date.now()});c.updated_at=Date.now();saveDb(db);}
  function sseError(message,requestId){return new Response(new ReadableStream({start(controller){controller.enqueue(enc.encode(`event: error\ndata: ${JSON.stringify({message,messageId:requestId})}\n\n`));controller.close();}}),{status:200,headers:{'Content-Type':'text/event-stream; charset=utf-8','Cache-Control':'no-cache'}});}
  async function accessCode(){return window.VEYRO_AUTH?.token||'';}
  async function callBackend(payload,controller,retry=true){
    const code=await accessCode(false);if(!code)throw Object.assign(Error('Código de acesso necessário.'),{status:401});
    const r=await localFetch(API+(LIVE?'/api/chat':'/api/chat/demo'),{method:'POST',headers:{'Content-Type':'application/json',Authorization:'Bearer '+code},body:JSON.stringify(payload),signal:controller.signal,mode:'cors'});
    if(r.status===401){window.VEYRO_AUTH?.logout();throw Object.assign(Error('Sessão encerrada. Entre novamente.'),{status:401});}
    if(!r.ok){let msg='A Veyro não conseguiu responder agora.';try{const d=await r.json();if(d?.error)msg=d.error;}catch{}throw Object.assign(Error(msg),{status:r.status});}
    return r;
  }
  async function remoteMessage(path,init){
    let body={};try{body=typeof init?.body==='string'?JSON.parse(init.body):init?.body||{};}catch{return localFetch(path,init);}
    const m=new URL(path,location.origin).pathname.match(/^\/api\/conversations\/([^/]+)\/messages$/);if(!m)return localFetch(path,init);
    const db=loadDb(),c=conversation(db,m[1]);if(!db||!c)return localFetch(path,init);
    const requestId=body.requestId||crypto.randomUUID(),ts=Date.now(),message=String(body.message||'').trim();
    if(!message)return localFetch(path,init);
    if(c.messages.some(x=>x.id===requestId))return sseError('Este envio já foi registrado.',requestId);
    const userMsg={id:requestId+'-user',role:'user',text:message,status:'COMPLETE',attachments:[],created_at:ts,updated_at:ts};
    const assistant={id:requestId,role:'assistant',text:'',status:'RUNNING',attachments:[],tool:null,created_at:ts+1,updated_at:ts+1};
    c.messages.push(userMsg,assistant);if(!c.manual_title&&c.title==='Nova conversa')c.title=message.slice(0,60);c.draft='';c.updated_at=ts;saveDb(db);
    const recent=c.messages.filter(x=>x.status==='COMPLETE'&&['user','assistant'].includes(x.role)).slice(-12).map(x=>({role:x.role,content:String(x.text||'').slice(0,5000)}));
    const payload={requestId,message,researchMode:body.researchMode||'STANDARD',recentMessages:recent,memories:memFor(db,c),project:projectFor(db,c)};
    const control=new AbortController();active.set(requestId,control);
    let remote;try{remote=await callBackend(payload,control);}catch(e){updateAssistant(db,c,requestId,{status:e.name==='AbortError'?'CANCELLED':'FAILED',text:''});active.delete(requestId);return sseError(e.message||'Não foi possível concluir.',requestId);}
    const reader=remote.body.getReader(),decoder=new TextDecoder();let buffer='',out='';
    return new Response(new ReadableStream({async start(controller){
      try{
        for(;;){const {value,done}=await reader.read();if(done)break;const chunk=decoder.decode(value,{stream:true});controller.enqueue(enc.encode(chunk));buffer+=chunk.replace(/\r/g,'');let cut;while((cut=buffer.indexOf('\n\n'))>=0){const block=buffer.slice(0,cut);buffer=buffer.slice(cut+2);const ev=block.split('\n').find(l=>l.startsWith('event:'))?.slice(6).trim();const data=block.split('\n').filter(l=>l.startsWith('data:')).map(l=>l.slice(5).trimStart()).join('\n');let d={};try{d=JSON.parse(data);}catch{}if(ev==='token'&&d.text){out+=d.text;updateAssistant(db,c,requestId,{text:out,status:'RUNNING'});}if(ev==='done')updateAssistant(db,c,requestId,{text:out,status:'COMPLETE'});if(ev==='error')updateAssistant(db,c,requestId,{text:out,status:'FAILED'});if(ev==='cancelled')updateAssistant(db,c,requestId,{text:out,status:'CANCELLED'});}}
      }catch(e){updateAssistant(db,c,requestId,{text:out,status:e.name==='AbortError'?'CANCELLED':'FAILED'});try{controller.enqueue(enc.encode(`event: error\ndata: ${JSON.stringify({message:'A resposta foi interrompida.',messageId:requestId})}\n\n`));}catch{}}
      finally{active.delete(requestId);try{reader.releaseLock();}catch{}controller.close();}
    },cancel(){control.abort();active.delete(requestId);}}),{headers:{'Content-Type':'text/event-stream; charset=utf-8','Cache-Control':'no-cache'}});
  }
  async function remoteStatus(path,init){
    try{const code=window.VEYRO_AUTH?.token||'';const r=await localFetch(API+'/api/health',{headers:code?{Authorization:'Bearer '+code}:{},mode:'cors'});const h=await r.json();if(!r.ok)throw Error();if(path==='/api/health/model')return Response.json(LIVE?
     {configured:h.modelConfigured&&h.liveEnabled,reachable:h.modelConfigured&&h.liveEnabled,provider:'openai',model:h.model||null,simulated:false}:
     {configured:true,reachable:true,provider:'demo',model:'resposta demonstrativa',simulated:true},{status:LIVE&&(!h.modelConfigured||!h.liveEnabled)?503:200});const base=await localFetch(path,init),data=await base.json();return Response.json({...data,chat:LIVE&&h.liveEnabled&&h.modelConfigured,chatProvider:LIVE&&h.liveEnabled&&h.modelConfigured?'openai-test':'demo-sem-ia',developmentVersion:'0.2.0'});}catch{return localFetch(path,init);}
  }
  window.fetch=(input,init={})=>{
    const value=typeof input==='string'?input:input?.url||'';
    if(!API)return localFetch(input,init);
    const url=new URL(value,location.origin),method=(init.method||'GET').toUpperCase();
    if(method==='POST'&&/^\/api\/conversations\/[^/]+\/messages$/.test(url.pathname))return remoteMessage(value,init);
    if(method==='POST'&&/^\/api\/conversations\/[^/]+\/cancel$/.test(url.pathname)){let body={};try{body=JSON.parse(init.body||'{}');}catch{}active.get(body.requestId)?.abort();return localFetch(input,init);}
    if(method==='GET'&&(url.pathname==='/api/status'||url.pathname==='/api/health/model'))return remoteStatus(url.pathname,init);
    return localFetch(input,init);
  };
  if(API){banner(LIVE?'MODO TESTE · API REAL':'MODO DEMONSTRAÇÃO · SEM IA · SEM CUSTO DE API',true);}
})();
