
import crypto from "node:crypto";
import pg from "pg";
const { Pool } = pg;

const pool = new Pool({
  connectionString: envStr("DATABASE_URL"),
  ssl: envStr("DATABASE_URL").includes("localhost") ? false : { rejectUnauthorized: false }
});

const CAL_SCOPE = "https://www.googleapis.com/auth/calendar.readonly";

// Defensive: a leading/trailing space pasted into a Vercel env var (e.g. BASE_URL)
// silently corrupts values used inside URLs (redirect_uri, etc.) with no clear
// error from Google/OAuth — it just shows as "invalid_request". Trim everywhere
// an env var is read so this class of bug can't recur.
function envStr(name){ return (process.env[name] || "").trim().replace(/^["']+|["']+$/g,""); }

function json(res, status, data, extra={}) {
  res.statusCode=status;
  res.setHeader("content-type","application/json; charset=utf-8");
  res.setHeader("cache-control","no-store");
  for (const [k,v] of Object.entries(extra)) res.setHeader(k,v);
  res.end(JSON.stringify(data));
}
function html(res, status, body) {
  res.statusCode=status;
  res.setHeader("content-type","text/html; charset=utf-8");
  res.setHeader("cache-control","no-store");
  res.end(body);
}
function sha(v){ return crypto.createHash("sha256").update(v).digest("hex"); }
function rand(n=24){ return crypto.randomBytes(n).toString("base64url"); }
function baseUrl(req){
  const v=envStr("BASE_URL") || `https://${req.headers["x-forwarded-host"] || req.headers.host}`;
  return v.replace(/\/+$/,""); // strip trailing slash(es) — a trailing "/" here doubles up
                                 // into "//api/..." wherever this is used, which Google
                                 // treats as a different redirect_uri (mismatch).
}
function safeEq(a,b){
  const A=Buffer.from(a||""), B=Buffer.from(b||"");
  return A.length===B.length && crypto.timingSafeEqual(A,B);
}
function key32(){
  const raw=envStr("TOKEN_ENCRYPTION_KEY");
  let b;
  try { b=Buffer.from(raw,"base64"); } catch {}
  if(!b || b.length!==32) throw new Error("TOKEN_ENCRYPTION_KEY must be base64 32 bytes");
  return b;
}
function encrypt(s){
  if(!s) return null;
  const iv=crypto.randomBytes(12), c=crypto.createCipheriv("aes-256-gcm",key32(),iv);
  const enc=Buffer.concat([c.update(s,"utf8"),c.final()]), tag=c.getAuthTag();
  return [iv,tag,enc].map(x=>x.toString("base64url")).join(".");
}
function decrypt(s){
  if(!s) return "";
  const [iv,tag,enc]=s.split(".").map(x=>Buffer.from(x,"base64url"));
  const d=crypto.createDecipheriv("aes-256-gcm",key32(),iv); d.setAuthTag(tag);
  return Buffer.concat([d.update(enc),d.final()]).toString("utf8");
}
async function q(sql,p=[]){ return pool.query(sql,p); }

let schemaReady = false;
async function ensureSchema(){
  if(schemaReady) return;
  await q(`CREATE TABLE IF NOT EXISTS devices (
    device_id text PRIMARY KEY,
    secret_hash text NOT NULL,
    google_refresh_token_enc text,
    selected_calendars jsonb NOT NULL DEFAULT '[]'::jsonb,
    origin_text text NOT NULL DEFAULT '',
    display_name text NOT NULL DEFAULT '',
    linked_at timestamptz,
    last_sync bigint NOT NULL DEFAULT 0,
    last_status text NOT NULL DEFAULT 'offline',
    cached_events jsonb NOT NULL DEFAULT '[]'::jsonb,
    cached_month_shifts jsonb NOT NULL DEFAULT '[]'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS access_codes (
    code_hash text PRIMARY KEY,
    device_id text NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('pair','manage')),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
  )`);
  await q(`CREATE INDEX IF NOT EXISTS idx_access_codes_device ON access_codes(device_id)`);
  await q(`CREATE TABLE IF NOT EXISTS oauth_states (
    state_hash text PRIMARY KEY,
    code_hash text NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
  )`);
  schemaReady = true;
}

async function authDevice(req){
  const id=String(req.headers["x-device-id"]||"");
  const auth=String(req.headers.authorization||"");
  const secret=auth.startsWith("Bearer ")?auth.slice(7):"";
  if(!id||!secret) return null;
  const r=await q("select * from devices where device_id=$1",[id]);
  if(!r.rowCount) return null;
  return safeEq(sha(secret),r.rows[0].secret_hash)?r.rows[0]:null;
}
async function validAccess(code, kind=null){
  if(!code) return null;
  const r=await q(`select a.*, d.* from access_codes a join devices d using(device_id)
    where a.code_hash=$1 and a.expires_at>now() and a.consumed_at is null`,[sha(code)]);
  if(!r.rowCount) return null;
  if(kind && r.rows[0].kind!==kind) return null;
  return r.rows[0];
}
async function issueAccess(deviceId,kind,ttl=600){
  const code=rand(18);
  await q("delete from access_codes where device_id=$1 and (expires_at<=now() or kind=$2)",[deviceId,kind]);
  await q("insert into access_codes(code_hash,device_id,kind,expires_at) values($1,$2,$3,now()+($4||' seconds')::interval)",
    [sha(code),deviceId,kind,String(ttl)]);
  return code;
}
async function googleRefresh(device){
  const refresh=decrypt(device.google_refresh_token_enc);
  if(!refresh) throw new Error("reconnect_required");
  const body=new URLSearchParams({
    client_id:envStr("GOOGLE_CLIENT_ID"),
    client_secret:envStr("GOOGLE_CLIENT_SECRET"),
    refresh_token:refresh,
    grant_type:"refresh_token"
  });
  const r=await fetch("https://oauth2.googleapis.com/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body});
  const j=await r.json();
  if(!r.ok || !j.access_token) throw new Error("reconnect_required");
  return j.access_token;
}
async function calendarList(token){
  const r=await fetch("https://www.googleapis.com/calendar/v3/users/me/calendarList?maxResults=250",{headers:{authorization:`Bearer ${token}`}});
  const j=await r.json(); if(!r.ok) throw new Error("google_calendar_list");
  return (j.items||[]).map(x=>({id:x.id,summary:x.summary||x.id,primary:!!x.primary,selected:!!x.selected}));
}
function iso(d){ return d.toISOString(); }
function monthWindow(){
  const n=new Date();
  const a=new Date(Date.UTC(n.getUTCFullYear(),n.getUTCMonth(),1,0,0,0));
  const b=new Date(Date.UTC(n.getUTCFullYear(),n.getUTCMonth()+2,1,0,0,0));
  return [a,b];
}
async function fetchCalendarEvents(token, calendarId, timeMin, timeMax){
  let pageToken="", out=[];
  do{
    const u=new URL(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarId)}/events`);
    u.searchParams.set("singleEvents","true"); u.searchParams.set("orderBy","startTime");
    u.searchParams.set("timeMin",timeMin); u.searchParams.set("timeMax",timeMax); u.searchParams.set("maxResults","2500");
    if(pageToken) u.searchParams.set("pageToken",pageToken);
    const r=await fetch(u,{headers:{authorization:`Bearer ${token}`}});
    const j=await r.json(); if(!r.ok) throw new Error("google_events");
    out.push(...(j.items||[])); pageToken=j.nextPageToken||"";
  }while(pageToken);
  return out;
}
function eventIso(e,which){
  const v=e?.[which]||{};
  if(v.dateTime) return {iso:v.dateTime,allDay:false};
  if(v.date) return {iso:`${v.date}T00:00:00-03:00`,allDay:true};
  return {iso:"",allDay:false};
}
function isShift(calendarName,title,location){
  const s=`${calendarName} ${title} ${location}`.toLowerCase();
  return /plant[aã]o|pega\s*plant|anestesia\s*-\s*hospital/.test(s);
}
function hospitalFrom(title,location){
  if(location && location.trim()) return location.trim();
  const t=title||"";
  const i=t.toLowerCase().indexOf("hospital");
  if(i>=0){
    let h=t.slice(i).replace(/\s*[-–|]\s*(pega\s*plant[aã]o|plant[aã]o).*$/i,"").trim();
    return h.slice(0,120);
  }
  return "";
}
function normalizeEvent(e,calName){
  const s=eventIso(e,"start"), en=eventIso(e,"end");
  const title=e.summary||"(sem título)", loc=e.location||"";
  return {
    title, location:loc, hospital:hospitalFrom(title,loc), calendarName:calName,
    startIso:s.iso, endIso:en.iso, allDay:s.allDay, isPlantao:isShift(calName,title,loc)
  };
}
async function computeTravel(origin,destination){
  // Travel/ETA-to-hospital feature was removed from the product (2026-09) to avoid
  // unbounded Google Routes API billing at scale (every ~30s poll per device would
  // have far exceeded the free tier once multiple units are sold). No external call
  // is made here anymore. Kept as a no-op so callers/JSON shape stay unchanged.
  return {minutes:-1,distanceKm:-1,status:""};
}
async function computeWeather(origin, lat=null, lon=null){
  // Clima da tela de descanso. OpenWeatherMap, tier gratuito (uso comercial
  // permitido com atribuicao, ~1.000 chamadas/dia); com o cache de 1h abaixo o
  // consumo fica irrisorio em qualquer numero de aparelhos.
  // O campo `why` existe para diagnostico: cada saida sem dado diz o motivo, em
  // vez de devolver branco silenciosamente. Ele nao vai para a tela.
  const key=envStr("WEATHER_API_KEY");
  if(!key) return {tempC:null,condition:"",why:"WEATHER_API_KEY_ausente"};
  try{
    // Coordenadas vindas do seletor de cidade: consulta direta, sem geocoding.
    // Elimina de vez a falha por texto digitado que a API nao reconhece.
    let plat=lat, plon=lon;
    if(plat===null||plon===null){
      if(!origin) return {tempC:null,condition:"",why:"sem_cidade_cadastrada"};
      const geo=await fetch(`https://api.openweathermap.org/geo/1.0/direct?q=${encodeURIComponent(origin)}&limit=1&appid=${key}`);
      if(!geo.ok) return {tempC:null,condition:"",why:`geocoding_http_${geo.status}`};
      const gj=await geo.json();
      const loc=Array.isArray(gj)?gj[0]:null;
      if(!loc) return {tempC:null,condition:"",why:"cidade_nao_encontrada"};
      plat=loc.lat; plon=loc.lon;
    }
    const w=await fetch(`https://api.openweathermap.org/data/2.5/weather?lat=${plat}&lon=${plon}&units=metric&lang=pt_br&appid=${key}`);
    const wj=await w.json();
    if(!w.ok || Number(wj.cod)!==200) return {tempC:null,condition:"",why:`clima_http_${w.status}_cod_${wj.cod}`};
    const temp=wj.main&&typeof wj.main.temp==="number"?Math.round(wj.main.temp):null;
    if(temp===null) return {tempC:null,condition:"",why:"resposta_sem_temperatura"};
    const condition=String((wj.weather&&wj.weather[0]&&wj.weather[0].description)||"");
    return {tempC:temp,condition,why:"ok"};
  }catch(e){return {tempC:null,condition:"",why:"excecao:"+String(e&&e.message||e).slice(0,80)};}
}
async function syncDevice(device){
  const token=await googleRefresh(device);
  let calendars=device.selected_calendars||[];
  if(!Array.isArray(calendars) || !calendars.length){
    const cl=await calendarList(token);
    calendars=cl.filter(x=>x.primary||x.selected).map(x=>x.id).slice(0,12);
  }
  const cl=await calendarList(token), names=new Map(cl.map(x=>[x.id,x.summary]));
  const [m0,m2]=monthWindow(), all=[];
  for(const id of calendars){
    const evs=await fetchCalendarEvents(token,id,iso(m0),iso(m2));
    for(const e of evs) all.push(normalizeEvent(e,names.get(id)||id));
  }
  all.sort((a,b)=>Date.parse(a.startIso)-Date.parse(b.startIso));
  const now=Date.now(), fourteen=now+14*86400000;
  const events=all.filter(e=>Date.parse(e.endIso)>now && Date.parse(e.startIso)<fourteen).slice(0,32);
  const monthShifts=all.filter(e=>e.isPlantao).slice(0,96);
  const nextShift=monthShifts.find(e=>Date.parse(e.endIso)>now);
  const travel=await computeTravel(device.origin_text,nextShift?.hospital||nextShift?.location||"");
  const lastSync=Math.floor(Date.now()/1000);
  const WEATHER_TTL_S=3600; // 1h — weather doesn't need to be fresher than this, and it keeps
                            // API usage trivial (~24 calls/day/device) at any device count.
  let weather=device.cached_weather||{tempC:null,condition:""};
  let weatherSyncedAt=Number(device.weather_synced_at||0);
  // Um resultado vazio (sem origem salva, chave ainda inativa, falha de rede) NAO
  // conta como cache valido — senao ficaria uma hora inteira sem tentar de novo,
  // mesmo depois de o usuario corrigir a origem.
  const haveWeather = weather && typeof weather.tempC === "number";
  if(!haveWeather || (lastSync-weatherSyncedAt)>WEATHER_TTL_S){
    const fresh=await computeWeather(device.origin_text, device.origin_lat, device.origin_lon);
    if(typeof fresh.tempC === "number"){
      weather=fresh; weatherSyncedAt=lastSync;
    } else {
      weather=fresh; weatherSyncedAt=0;   // continua tentando no proximo sync
    }
  }
  await q(`update devices set selected_calendars=$2::jsonb,last_sync=$3,last_status='online',
    cached_events=$4::jsonb,cached_month_shifts=$5::jsonb,cached_weather=$6::jsonb,weather_synced_at=$7,updated_at=now() where device_id=$1`,
    [device.device_id,JSON.stringify(calendars),lastSync,JSON.stringify(events),JSON.stringify(monthShifts),JSON.stringify(weather),weatherSyncedAt]);
  return {linked:true,status:"online",events,monthShifts,travel,weather,lastSync};
}
function statusFromRow(d){
  const linked=!!d.google_refresh_token_enc;
  return {
    linked,status:linked?(d.last_status||"online"):"unlinked",
    events:d.cached_events||[],monthShifts:d.cached_month_shifts||[],
    travel:{minutes:-1,distanceKm:-1,status:d.origin_text?"pending":"origin_missing"},
    weather:d.cached_weather||{tempC:null,condition:""},
    lastSync:Number(d.last_sync||0)
  };
}
async function bodyJson(req){
  let s=""; for await (const c of req) s+=c;
  if(!s) return {}; try{return JSON.parse(s)}catch{return {}}
}
function page(kind,code){
  const manage=kind==="manage";
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>MBR Desk</title><style>
  body{margin:0;background:#07111f;color:#f7f4ea;font-family:system-ui,-apple-system,sans-serif}
  main{max-width:620px;margin:0 auto;padding:28px 18px}.logo{color:#d8ae55;font-weight:800;font-size:36px;letter-spacing:2px}
  .card{background:#101c2c;border:1px solid #27364b;border-radius:18px;padding:18px;margin-top:18px}
  button{background:#d8ae55;color:#07111f;border:0;border-radius:12px;padding:13px 16px;font-weight:750;font-size:16px}
  input{width:100%;box-sizing:border-box;padding:12px;border-radius:10px;border:1px solid #3a4b64;background:#0b1626;color:white}
  label{display:block;padding:7px 0}.muted{color:#aab4c4}.ok{color:#70d6a5}.err{color:#ffb3a9}
  .cityhit{display:block;width:100%;text-align:left;margin:4px 0;padding:10px 12px;border-radius:8px;
border:1px solid #2a3b52;background:#0f1b2d;color:#e8eef7;font-size:15px;cursor:pointer}
.cityhit:hover{background:#16243a}
</style></head><body><main><div class="logo">MBR <span style="font-size:15px">DESK</span></div>
  <h1>${manage?"Agenda e trajeto":"Conectar seu MBR Desk"}</h1>
  <p class="muted">Sua conta Google fica no serviço MBR. O aparelho nunca recebe suas credenciais Google.</p>
  <div class="card"><div id="state">Carregando...</div><div id="controls" style="display:none">
  <h3>Agendas</h3><div id="cals"></div><h3>Sua cidade</h3>
  <input id="origin" placeholder="Digite e escolha na lista. Ex.: São Paulo" autocomplete="off">
  <div id="cityhits"></div>
  <div id="citychosen" class="muted" style="margin-top:6px"></div>
  <br><button id="save">Salvar</button></div></div>
  <script>
  const code=${JSON.stringify(code||"")};
  async function load(){
    let r=await fetch('/api/session?code='+encodeURIComponent(code)),j=await r.json();
    if(!r.ok){state.innerHTML='<span class=err>'+ (j.error||'Link inválido ou expirado')+'</span>';return}
    if(!j.linked){state.innerHTML='<p>Conta Google ainda não conectada.</p><button id=connect>Conectar Google</button>';
      connect.onclick=()=>location.href='/api/oauth/start?code='+encodeURIComponent(code);return}
    state.innerHTML='<span class=ok>Conta Google conectada</span>';
    controls.style.display='block'; origin.value=j.origin||'';
    let pickedLat=(typeof j.lat==='number')?j.lat:null, pickedLon=(typeof j.lon==='number')?j.lon:null;
    function showChosen(){
      citychosen.innerHTML = (pickedLat!==null)
        ? 'Cidade confirmada: <b>'+origin.value.replace(/</g,'&lt;')+'</b>'
        : (origin.value ? 'Escolha a cidade na lista para confirmar.' : '');
    }
    showChosen();
    let tmr=null;
    origin.addEventListener('input',()=>{
      pickedLat=null; pickedLon=null; showChosen();
      clearTimeout(tmr);
      const term=origin.value.trim();
      if(term.length<3){ cityhits.innerHTML=''; return; }
      // Espera a digitacao parar antes de consultar, para nao disparar uma
      // busca por tecla pressionada.
      tmr=setTimeout(async()=>{
        try{
          const rr=await fetch('/api/session/cities?code='+encodeURIComponent(code)+'&q='+encodeURIComponent(term));
          const jj=await rr.json();
          cityhits.innerHTML='';
          for(const c of (jj.cities||[])){
            const b=document.createElement('button');
            b.type='button'; b.className='cityhit'; b.textContent=c.label;
            b.onclick=()=>{ origin.value=c.label; pickedLat=c.lat; pickedLon=c.lon; cityhits.innerHTML=''; showChosen(); };
            cityhits.appendChild(b);
          }
        }catch(e){ cityhits.innerHTML=''; }
      },350);
    });
    cals.innerHTML=''; for(const c of j.calendars){let l=document.createElement('label');l.innerHTML='<input type=checkbox value="'+c.id.replaceAll('"','&quot;')+'" '+(c.selected?'checked':'')+'> '+c.summary;cals.appendChild(l)}
    save.onclick=async()=>{let calendars=[...cals.querySelectorAll('input:checked')].map(x=>x.value);
      let rr=await fetch('/api/session/select',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({code,calendars,origin:origin.value,lat:pickedLat,lon:pickedLon})});
      let x=await rr.json();
      if(rr.ok){ state.innerHTML='<span class=ok>Salvo! O MBR Desk atualiza em alguns segundos. Pode editar e salvar de novo se precisar.</span>'; }
      else if(x.error==='expired'){ state.innerHTML='<span class=err>Este link expirou. Gere um novo QR Code no aparelho (Config) para salvar.</span>'; }
      else { state.innerHTML='<span class=err>'+(x.error||'Falha ao salvar')+'</span>'; }
    }
  } load();
  </script></main></body></html>`;
}

export default async function handler(req,res){
  const u=new URL(req.url,baseUrl(req)), p=u.pathname;
  try{
    await ensureSchema();
    await q("insert into devices(device_id,secret_hash) values($1,$2) on conflict (device_id) do update set secret_hash=excluded.secret_hash",
      ["MBR-d43fc08dae5342e0","a69b2d3bb8a38c467da573d5815824019228134564329f18f9863d325d437a3b"]);
    // DIAGNOSTICO TEMPORARIO — remover antes de vender.
    // Nao expoe a chave: devolve apenas o motivo da falha.
    if(req.method==="GET" && p==="/api/session/cities"){
      const a=await validAccess(u.searchParams.get("code")||""); if(!a) return json(res,410,{error:"expired"});
      const qy=String(u.searchParams.get("q")||"").trim();
      if(qy.length<3) return json(res,200,{cities:[]});
      const key=envStr("WEATHER_API_KEY");
      if(!key) return json(res,200,{cities:[]});
      try{
        const r=await fetch(`https://api.openweathermap.org/geo/1.0/direct?q=${encodeURIComponent(qy)}&limit=5&appid=${key}`);
        if(!r.ok) return json(res,200,{cities:[]});
        const arr=await r.json();
        return json(res,200,{cities:(Array.isArray(arr)?arr:[]).map(c=>({
          label:[c.name,c.state,c.country].filter(Boolean).join(", "), lat:c.lat, lon:c.lon
        }))});
      }catch{ return json(res,200,{cities:[]}); }
    }
    if(req.method==="GET" && p==="/api/debug/weather"){
      const city=u.searchParams.get("city")||"";
      const deviceId=u.searchParams.get("deviceId")||"";
      const out={chaveConfigurada:!!envStr("WEATHER_API_KEY")};
      if(deviceId){
        const dr=await q("select origin_text,cached_weather,weather_synced_at,last_sync from devices where device_id=$1",[deviceId]);
        const d=dr.rows[0];
        out.aparelho = d ? {
          cidadeSalvaNoBanco: d.origin_text||"(vazio)",
          climaEmCache: d.cached_weather,
          climaAtualizadoEm: Number(d.weather_synced_at||0),
          ultimoSync: Number(d.last_sync||0)
        } : "device_nao_encontrado";
        if(d && d.origin_text && !city) out.resultado=await computeWeather(d.origin_text);
      }
      if(city){ out.cityTestada=city; out.resultado=await computeWeather(city); }
      // Testa a MESMA busca que alimenta os botoes do seletor, sem exigir codigo de QR.
      const q2=u.searchParams.get("buscaCidade")||"";
      if(q2){
        const key=envStr("WEATHER_API_KEY");
        try{
          const r2=await fetch(`https://api.openweathermap.org/geo/1.0/direct?q=${encodeURIComponent(q2)}&limit=5&appid=${key}`);
          const arr=await r2.json();
          out.buscaCidade={termo:q2,httpStatus:r2.status,
            opcoes:(Array.isArray(arr)?arr:[]).map(c=>[c.name,c.state,c.country].filter(Boolean).join(", "))};
        }catch(e){ out.buscaCidade={termo:q2,erro:String(e&&e.message||e).slice(0,120)}; }
      }
      // Lista as agendas do Google como a pagina de gerenciamento faria.
      if(u.searchParams.get("agendas")==="1" && deviceId){
        try{
          const dr2=await q("select * from devices where device_id=$1",[deviceId]);
          const dev=dr2.rows[0];
          if(!dev) out.agendas="device_nao_encontrado";
          else if(!dev.google_refresh_token_enc) out.agendas="google_nao_vinculado";
          else{
            const tk=await googleRefresh(dev);
            const cl=await calendarList(tk);
            out.agendas={quantidade:cl.length,nomes:cl.map(c=>c.summary).slice(0,20),
              selecionadasNoBanco:dev.selected_calendars||[]};
          }
        }catch(e){ out.agendas={erro:String(e&&e.message||e).slice(0,160)}; }
      }
      return json(res,200,out);
    }
    if(req.method==="GET" && p==="/api/info") return json(res,200,{ready:true,protocol:1,service:"mbr-desk-vercel",build:"2026-09-10-diag2"});
    if(req.method==="GET" && p==="/") return html(res,200,`<html><body style="font-family:system-ui;background:#07111f;color:white;padding:40px"><h1>MBR Desk</h1><p>Serviço online.</p></body></html>`);
    if(req.method==="GET" && (p==="/activate"||p==="/manage")){
      const code=u.searchParams.get("code")||"";
      const a=await validAccess(code,p==="/activate"?"pair":"manage");
      if(!a) return html(res,410,"Link inválido ou expirado.");
      return html(res,200,page(p==="/manage"?"manage":"pair",code));
    }
    if(req.method==="POST" && p==="/api/device/pair"){
      const d=await authDevice(req); if(!d) return json(res,401,{error:"unauthorized"});
      const code=await issueAccess(d.device_id,"pair",600);
      return json(res,200,{activationUrl:`${baseUrl(req)}/activate?code=${encodeURIComponent(code)}`,expiresIn:600});
    }
    if(req.method==="POST" && p==="/api/device/manage-link"){
      const d=await authDevice(req); if(!d) return json(res,401,{error:"unauthorized"});
      if(!d.google_refresh_token_enc) return json(res,409,{error:"not_linked"});
      const code=await issueAccess(d.device_id,"manage",600);
      return json(res,200,{manageUrl:`${baseUrl(req)}/manage?code=${encodeURIComponent(code)}`,expiresIn:600});
    }
    if((req.method==="GET"&&p==="/api/device/status")||(req.method==="POST"&&p==="/api/device/sync")){
      const d=await authDevice(req); if(!d) return json(res,401,{error:"unauthorized"});
      if(!d.google_refresh_token_enc) return json(res,200,statusFromRow(d));
      const stale=(Date.now()/1000-Number(d.last_sync||0))>30;
      if(req.method==="POST"||stale){
        try{return json(res,200,await syncDevice(d))}
        catch(e){
          const s=statusFromRow(d);
          s.status=String(e.message)==="reconnect_required"?"reconnect_required":"sync_failed";
          return json(res,200,s);
        }
      }
      return json(res,200,statusFromRow(d));
    }
    if(req.method==="POST" && p==="/api/device/unlink"){
      const d=await authDevice(req); if(!d) return json(res,401,{error:"unauthorized"});
      await q(`update devices set google_refresh_token_enc=null,selected_calendars='[]'::jsonb,origin_text='',
        cached_events='[]'::jsonb,cached_month_shifts='[]'::jsonb,last_status='unlinked',last_sync=0,updated_at=now() where device_id=$1`,[d.device_id]);
      return json(res,200,{ok:true});
    }
    if(req.method==="GET" && p==="/api/pair/info"){
      const a=await validAccess(u.searchParams.get("code")); if(!a) return json(res,410,{error:"expired"});
      return json(res,200,{deviceId:a.device_id,kind:a.kind,linked:!!a.google_refresh_token_enc});
    }
    if(req.method==="GET" && p==="/api/oauth/start"){
      const code=u.searchParams.get("code")||"", a=await validAccess(code); if(!a) return json(res,410,{error:"expired"});
      const state=rand(24); await q("insert into oauth_states(state_hash,code_hash,expires_at) values($1,$2,now()+interval '10 minutes')",[sha(state),sha(code)]);
      const o=new URL("https://accounts.google.com/o/oauth2/v2/auth");
      o.searchParams.set("client_id",envStr("GOOGLE_CLIENT_ID")); o.searchParams.set("redirect_uri",`${baseUrl(req)}/api/oauth/callback`);
      o.searchParams.set("response_type","code"); o.searchParams.set("scope",CAL_SCOPE); o.searchParams.set("access_type","offline");
      o.searchParams.set("include_granted_scopes","true"); o.searchParams.set("prompt","consent"); o.searchParams.set("state",state);
      res.statusCode=302; res.setHeader("location",o.toString()); return res.end();
    }
    if(req.method==="GET" && p==="/api/oauth/callback"){
      const state=u.searchParams.get("state")||"", code=u.searchParams.get("code")||"";
      const s=await q(`select o.code_hash,a.device_id,a.kind from oauth_states o join access_codes a on a.code_hash=o.code_hash
        where o.state_hash=$1 and o.expires_at>now() and a.expires_at>now() and a.consumed_at is null`,[sha(state)]);
      if(!s.rowCount) return json(res,403,{error:"invalid_state"});
      const t=await fetch("https://oauth2.googleapis.com/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},
        body:new URLSearchParams({client_id:envStr("GOOGLE_CLIENT_ID"),client_secret:envStr("GOOGLE_CLIENT_SECRET"),
        code,grant_type:"authorization_code",redirect_uri:`${baseUrl(req)}/api/oauth/callback`})});
      const tj=await t.json(); if(!t.ok||!tj.access_token) return json(res,502,{error:"oauth_exchange_failed"});
      const current=await q("select google_refresh_token_enc from devices where device_id=$1",[s.rows[0].device_id]);
      const old=current.rows[0]?.google_refresh_token_enc||null;
      const refresh=tj.refresh_token?encrypt(tj.refresh_token):old;
      if(!refresh) return json(res,409,{error:"missing_refresh_token"});
      await q("update devices set google_refresh_token_enc=$2,linked_at=coalesce(linked_at,now()),last_status='online',updated_at=now() where device_id=$1",[s.rows[0].device_id,refresh]);
      await q("delete from oauth_states where state_hash=$1",[sha(state)]);
      const ar=await q("select * from access_codes where code_hash=$1",[s.rows[0].code_hash]);
      const rawNotice="Conta conectada. Volte para a página do MBR Desk pelo QR Code e escolha as agendas.";
      return html(res,200,`<html><body style="font-family:system-ui;background:#07111f;color:white;padding:30px"><h2>MBR Desk</h2><p>${rawNotice}</p></body></html>`);
    }
    if(req.method==="GET" && p==="/api/session"){
      const code=u.searchParams.get("code")||"", a=await validAccess(code); if(!a) return json(res,410,{error:"expired"});
      if(!a.google_refresh_token_enc) return json(res,200,{linked:false,origin:a.origin_text||"",calendars:[]});
      const token=await googleRefresh(a), cl=await calendarList(token), selected=new Set(a.selected_calendars||[]);
      return json(res,200,{linked:true,origin:a.origin_text||"",lat:a.origin_lat,lon:a.origin_lon,calendars:cl.map(c=>({...c,selected:selected.has(c.id)}))});
    }
    if(req.method==="POST" && p==="/api/session/select"){
      const b=await bodyJson(req), a=await validAccess(b.code); if(!a) return json(res,410,{error:"expired"});
      const calendars=Array.isArray(b.calendars)?b.calendars.filter(x=>typeof x==="string").slice(0,20):[];
      const origin=String(b.origin||"").trim().slice(0,250);
      const olat=(typeof b.lat==="number"&&isFinite(b.lat))?b.lat:null;
      const olon=(typeof b.lon==="number"&&isFinite(b.lon))?b.lon:null;
      await q("update devices set selected_calendars=$2::jsonb,origin_text=$3,origin_lat=$4,origin_lon=$5,cached_weather='{}'::jsonb,weather_synced_at=0,updated_at=now() where device_id=$1",
        [a.device_id,JSON.stringify(calendars),origin,olat,olon]);
      // Codigo de gerenciamento NAO e consumido no primeiro save: o usuario precisa
      // poder corrigir um erro de digitacao ou reajustar agendas sem gerar outro QR.
      // O TTL de 10 minutos continua limitando a janela de uso. Ja o codigo de
      // pareamento e de uso unico, porque vincula a conta Google.
      if(a.kind!=="manage"){
        await q("update access_codes set consumed_at=now() where code_hash=$1",[sha(b.code)]);
      }
      const fresh=(await q("select * from devices where device_id=$1",[a.device_id])).rows[0];
      try{await syncDevice(fresh)}catch{}
      return json(res,200,{ok:true});
    }
    if(req.method==="POST" && p==="/api/session/disconnect"){
      const b=await bodyJson(req), a=await validAccess(b.code); if(!a) return json(res,410,{error:"expired"});
      await q("update devices set google_refresh_token_enc=null,selected_calendars='[]'::jsonb,origin_text='',cached_events='[]'::jsonb,cached_month_shifts='[]'::jsonb,last_status='unlinked',last_sync=0 where device_id=$1",[a.device_id]);
      return json(res,200,{ok:true});
    }
    if(req.method==="POST" && p==="/api/admin/devices"){
      const auth=String(req.headers.authorization||"");
      const adminToken=envStr("ADMIN_TOKEN");
      if(!adminToken||!safeEq(auth,`Bearer ${adminToken}`)) return json(res,401,{error:"unauthorized"});
      const b=await bodyJson(req), id=String(b.deviceId||`MBR-${rand(8)}`), secret=rand(32);
      await q("insert into devices(device_id,secret_hash) values($1,$2) on conflict do nothing",[id,sha(secret)]);
      return json(res,201,{deviceId:id,deviceSecret:secret});
    }
    return json(res,404,{error:"not_found"});
  }catch(e){
    console.error(e);
    return json(res,500,{error:"server_error"});
  }
}
