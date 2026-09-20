'use strict';
(()=>{
  // Veyro Chrome Test: backend local simulado para testar UX sem publicar nem usar APIs reais.
  const nativeFetch=window.fetch.bind(window);
  if(!crypto.randomUUID){crypto.randomUUID=()=>('xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx').replace(/[xy]/g,c=>{const r=Math.random()*16|0,v=c==='x'?r:(r&3|8);return v.toString(16);});}
  const KEY='veyro_chrome_test_v010';
  const now=()=>Date.now();
  const uid=()=>crypto.randomUUID();
  const defaultState=()=>({
    photo:{prompt:'',operation:'generate',count:1,size:'1024x1024',sourceId:'',sceneId:'',preserve:''},
    editor:{clips:[],mode:'ASSISTED',intensity:'LOW',format:'original',resolution:'720',request:''},
    format:'auto',duration:null,original:'',draft:'',scenes:[],fileIds:[],review:true,visualStyle:'',characters:'',constraints:'',audio:false
  });
  function fresh(){return {profile:{name:'Usuário de teste',avatar:null,updatedAt:now()},projects:[],conversations:[],memories:[],versions:[],assets:[],photoJobs:[],runs:[]};}
  let db;
  try{db=JSON.parse(localStorage.getItem(KEY)||'null')||fresh();}catch{db=fresh();}
  const save=()=>{try{localStorage.setItem(KEY,JSON.stringify(db));}catch{}};
  const json=(x,status=200)=>new Response(JSON.stringify(x),{status,headers:{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'}});
  const parseBody=async init=>{if(!init?.body)return {};if(init.body instanceof FormData)return init.body;try{return JSON.parse(init.body)}catch{return {}}};
  const project=id=>db.projects.find(x=>x.id===id);
  const conversation=id=>db.conversations.find(x=>x.id===id&&!x.deleted);
  const projectData=p=>({
    project:{id:p.id,title:p.title,revision:p.revision,state:p.state},
    messages:[],
    memories:db.memories.filter(m=>m.scope!=='conversation'&&(m.project_id===p.id||m.scope==='user')),
    versions:db.versions.filter(v=>v.project_id===p.id).sort((a,b)=>b.created_at-a.created_at).map(({state,...v})=>v),
    assets:db.assets.filter(a=>a.project_id===p.id).map(({blobUrl,...a})=>a),
    runs:db.runs.filter(r=>r.project_id===p.id).sort((a,b)=>b.created_at-a.created_at),
    photoJobs:db.photoJobs.filter(j=>j.project_id===p.id)
  });
  function detectLevel(text){
    const t=(text||'').toLowerCase();
    let score=0;
    if(/pesquis|compare|fontes|atual|hoje|recente/.test(t))score+=2;
    if(/analise|explique bem|detalh|planej|estrateg|complex/.test(t))score+=2;
    if((text||'').length>350)score++;
    return score>=3?'DEEP':score>=1?'STANDARD':'FAST';
  }
  function demoReply(text){
    const level=detectLevel(text),t=(text||'').trim();
    if(/^(oi|olá|ola|e aí|e ai|bom dia|boa tarde|boa noite)[!. ]*$/i.test(t))return `Olá! 👋 Esta é a Veyro em modo de teste no Chrome. O fluxo do chat está funcionando. Nível detectado: ${level}.`;
    if(/\b(lembre|guarde|memorize|salve isso|não esqueça|nao esqueca)\b/i.test(t))return `Entendi. Neste modo de teste, a memória é salva somente neste navegador. Você pode conferir em Memórias.`;
    if(/\b(v[ií]deo|roteiro|cena)\b/i.test(t))return `Modo ${level}: recebi seu pedido sobre vídeo. Nesta prévia você consegue testar conversa, histórico, memória, navegação e o comportamento da interface. A geração real de vídeo ainda não está conectada.`;
    if(/\b(pesquis|internet|fonte|not[ií]cia|atual)\b/i.test(t))return `Modo ${level}: a Veyro identificaria necessidade de pesquisa. Nesta versão Chrome offline, a pesquisa externa está simulada para você testar o fluxo sem publicar nem usar credenciais.`;
    return `Modo ${level}: recebi “${t.slice(0,180)}${t.length>180?'…':''}”. Esta é uma resposta simulada para testar o chat, streaming, histórico e interface. A conexão com um modelo real será feita no ambiente de teste hospedado.`;
  }
  function streamEvents(events,request){
    const enc=new TextEncoder();
    return new Response(new ReadableStream({async start(controller){
      try{for(const item of events){if(request.cancelled){controller.enqueue(enc.encode(`event: cancelled\ndata: ${JSON.stringify({messageId:request.id,message:'Resposta interrompida.'})}\n\n`));break;}if(item.delay)await new Promise(r=>setTimeout(r,item.delay));controller.enqueue(enc.encode(`event: ${item.event}\ndata: ${JSON.stringify(item.data)}\n\n`));}}
      finally{controller.close();}
    }}),{headers:{'Content-Type':'text/event-stream; charset=utf-8','Cache-Control':'no-cache'}});
  }
  const active=new Map();
  async function api(path,init={}){
    const method=(init.method||'GET').toUpperCase();
    const url=new URL(path,'https://demo.invalid');
    const p=url.pathname.replace(/^\/api\//,'');
    const body=await parseBody(init);

    if(p==='status')return json({chat:true,chatProvider:'chrome-demo',video:false,images:false,storage:true,version:'0.7.0',developmentVersion:'0.1.0-chrome',research:{search:false,reader:false},embeddings:false,knowledge:true});
    if(p==='health')return json({ok:true,service:'veyro-chrome-demo',developmentVersion:'0.1.0'});
    if(p==='health/model')return json({configured:false,reachable:false,provider:'chrome-demo',model:null,simulated:true},503);
    if(p==='profile'&&method==='GET')return json(db.profile);
    if(p==='profile'&&method==='PUT'){db.profile={...db.profile,name:String(body.name||'Usuário de teste').slice(0,80),updatedAt:now()};save();return json(db.profile);}
    if(p==='profile/avatar')return json({error:'Foto de perfil não é persistida no modo ZIP.'},404);

    if(p==='projects'&&method==='GET')return json(db.projects.filter(x=>!x.deleted).sort((a,b)=>b.updated_at-a.updated_at).map(x=>({id:x.id,title:x.title,revision:x.revision,updated_at:x.updated_at})));
    if(p==='projects'&&method==='POST'){
      const id=uid(),ts=now();db.projects.push({id,title:String(body.title||'Meu primeiro projeto').slice(0,100),revision:0,state:defaultState(),created_at:ts,updated_at:ts});save();return json({id},201);
    }

    if(p==='conversations'&&method==='GET'){
      const archived=url.searchParams.get('archived')==='1',q=(url.searchParams.get('q')||'').toLowerCase();
      return json(db.conversations.filter(c=>!c.deleted&&!!c.archived===archived&&(!q||c.title.toLowerCase().includes(q)||c.messages.some(m=>(m.text||'').toLowerCase().includes(q)))).sort((a,b)=>b.updated_at-a.updated_at).map(({messages,...c})=>c));
    }
    if(p==='conversations'&&method==='POST'){
      const id=uid(),ts=now();db.conversations.push({id,project_id:body.projectId,title:'Nova conversa',draft:'',manual_title:0,archived:false,deleted:false,created_at:ts,updated_at:ts,messages:[]});save();return json({id},201);
    }
    let m=p.match(/^conversations\/([^/]+)(?:\/(messages|cancel|jobs))?$/);
    if(m){const c=conversation(m[1]);if(!c)return json({error:'Conversa não encontrada.'},404);
      if(!m[2]&&method==='GET')return json({conversation:{...c,messages:undefined},hasMore:false,messages:c.messages});
      if(!m[2]&&method==='PATCH'){if(body.title!==undefined){c.title=String(body.title).trim().slice(0,80)||c.title;c.manual_title=1;}if(body.draft!==undefined)c.draft=String(body.draft).slice(0,12000);if(body.archived!==undefined)c.archived=!!body.archived;c.updated_at=now();save();return json({ok:true});}
      if(!m[2]&&method==='DELETE'){c.deleted=true;c.title='Conversa excluída';c.messages=[];save();return json({ok:true});}
      if(m[2]==='jobs'&&method==='GET')return json([]);
      if(m[2]==='cancel'&&method==='POST'){const r=active.get(body.requestId);if(r)r.cancelled=true;const msg=c.messages.find(x=>x.id===body.requestId);if(msg)msg.status='CANCELLED';save();return json({ok:true});}
      if(m[2]==='messages'&&method==='POST'){
        const requestId=body.requestId||uid(),ts=now(),userMsg={id:requestId+'-user',role:'user',text:String(body.message||''),status:'COMPLETE',attachments:[],created_at:ts,updated_at:ts};
        const assistant={id:requestId,role:'assistant',text:'',status:'RUNNING',attachments:[],tool:null,created_at:ts+1,updated_at:ts+1};
        c.messages.push(userMsg,assistant);if(!c.manual_title&&c.title==='Nova conversa')c.title=(userMsg.text||'Conversa de teste').slice(0,60);c.draft='';c.updated_at=ts;save();
        const low=userMsg.text.toLowerCase();const memoryMatch=userMsg.text.match(/^(?:lembre(?:-se)?(?: disso)?|guarde(?: isso)?|memorize|salve isso|não esqueça|nao esqueca)\s*:?[ ]*([\s\S]+)$/i);
        if(memoryMatch&&memoryMatch[1].trim()){db.memories.push({id:uid(),scope:'project',text:memoryMatch[1].trim().slice(0,2000),project_id:c.project_id,conversation_id:null,revision:0,created_at:ts});save();}
        const reply=demoReply(userMsg.text),request={id:requestId,cancelled:false};active.set(requestId,request);
        const chunks=reply.match(/.{1,22}(?:\s|$)|.{1,22}/g)||[reply];
        const events=[{event:'status',data:{state:'thinking',requestId,title:c.title},delay:80},{event:'status',data:{state:'responding',requestId,level:detectLevel(userMsg.text)},delay:100},...chunks.map(ch=>({event:'token',data:{text:ch},delay:28})),{event:'done',data:{messageId:requestId},delay:40}];
        (async()=>{for(const ev of events){if(request.cancelled){assistant.status='CANCELLED';assistant.updated_at=now();save();active.delete(requestId);return;}if(ev.event==='token')assistant.text+=ev.data.text;if(ev.event==='done')assistant.status='COMPLETE';assistant.updated_at=now();await new Promise(r=>setTimeout(r,ev.delay||0));save();}active.delete(requestId);})();
        return streamEvents(events,request);
      }
    }

    if(p==='memory'&&method==='POST'){
      const id=uid(),scope=['user','project','conversation','system'].includes(body.scope)?body.scope:'project';db.memories.push({id,scope,text:String(body.text||'').trim().slice(0,2000),project_id:scope==='project'?body.projectId:null,conversation_id:scope==='conversation'?body.conversationId:null,revision:0,created_at:now()});save();return json({id},201);
    }
    if(p==='memory/search'&&method==='GET'){
      const pid=url.searchParams.get('projectId'),cid=url.searchParams.get('conversationId'),q=(url.searchParams.get('q')||'').toLowerCase();
      const memories=db.memories.filter(x=>(x.scope==='user'||x.scope==='system'||(x.scope==='project'&&x.project_id===pid)||(x.scope==='conversation'&&x.conversation_id===cid))&&(!q||x.text.toLowerCase().includes(q)));
      return json({mode:'palavras (teste local)',memories});
    }
    m=p.match(/^memory\/([^/]+)$/);if(m){const mem=db.memories.find(x=>x.id===m[1]);if(!mem)return json({error:'Memória não encontrada.'},404);if(method==='PATCH'){mem.text=String(body.text||'').trim().slice(0,2000);mem.revision=(mem.revision||0)+1;save();return json(mem);}if(method==='DELETE'){db.memories=db.memories.filter(x=>x.id!==m[1]);save();return json({ok:true});}}

    m=p.match(/^projects\/([^/]+)(?:\/(.*))?$/);if(m){const pr=project(m[1]),action=m[2]||'';if(!pr)return json({error:'Projeto não encontrado.'},404);
      if(!action&&method==='GET')return json(projectData(pr));
      if(!action&&method==='PUT'){
        db.versions.push({id:uid(),project_id:pr.id,label:'Versão salva (Chrome)',state:structuredClone(pr.state),created_at:now()});pr.state=body.state||pr.state;pr.title=String(body.title||pr.title).slice(0,100);pr.revision++;pr.updated_at=now();save();return json({revision:pr.revision});
      }
      if(action==='intent'&&method==='POST'){const s=String(body.text||'').toLowerCase();return json({tool:/\b(foto|imagem|retrato|capa)\b/.test(s)?'photo':/\b(cortar|acelerar|desacelerar|editar vídeo|editar video)\b/.test(s)?'editor':null});}
      if(action==='memories'){if(method==='POST'){const id=uid();db.memories.push({id,scope:body.scope==='global'?'user':'project',text:String(body.text||'').trim().slice(0,2000),project_id:body.scope==='global'?null:pr.id,conversation_id:null,revision:0,created_at:now()});save();return json({id},201);}if(method==='DELETE'){db.memories=db.memories.filter(x=>x.id!==body.id);save();return json({ok:true});}}
      let vm=action.match(/^versions\/([^/]+)$/);if(vm&&method==='GET'){const v=db.versions.find(x=>x.id===vm[1]&&x.project_id===pr.id);return v?json(v):json({error:'Versão não encontrada.'},404);}
      if(action==='restore'&&method==='POST'){const v=db.versions.find(x=>x.id===body.id&&x.project_id===pr.id);if(!v)return json({error:'Versão não encontrada.'},404);db.versions.push({id:uid(),project_id:pr.id,label:'Antes de restaurar',state:structuredClone(pr.state),created_at:now()});pr.state=structuredClone(v.state);pr.revision++;save();return json({revision:pr.revision});}
      if(action==='chat'&&method==='POST'){
        const text=String(body.text||''),id=uid(),ts=now(),reply=demoReply(text);db.runs.push({id,project_id:pr.id,status:'COMPLETE',revision:pr.revision,created_at:ts,updated_at:ts,tasks:[],output:{reply,scenes:pr.state.scenes||[],warnings:['Resposta simulada no modo Chrome ZIP.']}});save();return json({runId:id});
      }
      if(action==='apply'&&method==='POST')return json({revision:pr.revision});
      if(action==='assets'&&method==='POST'){
        const file=body instanceof FormData?body.get('file'):null;if(!file)return json({error:'Escolha um arquivo.'},400);const id=uid(),blobUrl=URL.createObjectURL(file),a={id,project_id:pr.id,name:file.name,mime:file.type||'application/octet-stream',size:file.size,metadata:{},created_at:now(),blobUrl};db.assets.push(a);save();return json(({blobUrl,...rest})=>rest)(a),201;
      }
      const am=action.match(/^assets\/([^/]+)$/);if(am&&method==='GET'){const a=db.assets.find(x=>x.id===am[1]&&x.project_id===pr.id);if(!a)return json({error:'Arquivo não encontrado.'},404);if(a.blobUrl)return nativeFetch(a.blobUrl);return json({error:'Arquivo disponível somente durante esta sessão.'},404);}
      if(action==='photo-jobs'&&method==='POST'){const job={id:uid(),project_id:pr.id,status:'WAITING',request:{count:body.settings?.count||1,...body.settings},outputs:[],created_at:now()};db.photoJobs.push(job);save();return json(job,201);}
      const pj=action.match(/^photo-jobs\/([^/]+)(?:\/(run|cancel))?$/);if(pj){const job=db.photoJobs.find(x=>x.id===pj[1]);if(!job)return json({error:'Pedido não encontrado.'},404);if(method==='GET')return json(job);if(pj[2]==='cancel'){job.status='CANCELLED';save();return json({ok:true});}if(pj[2]==='run')return json(job);}
    }
    return json({error:'Recurso não disponível no modo Chrome ZIP.'},404);
  }

  window.fetch=async(input,init={})=>{
    const value=typeof input==='string'?input:input?.url||'';
    if(value.startsWith('/api/'))return api(value,init);
    return nativeFetch(input,init);
  };
})();
