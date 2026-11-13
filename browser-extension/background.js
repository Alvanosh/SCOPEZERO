const SENSITIVE = /authorization|proxy-authorization|cookie|set-cookie|api[-_]?key|token|secret/i;
async function cfg(){ return await chrome.storage.local.get({enabled:false,baseUrl:'http://127.0.0.1:8888',scanId:'',rootDomain:'',token:'',captureBodies:false}); }
function inScope(host, root){ host=(host||'').toLowerCase().replace(/\.$/,''); root=(root||'').toLowerCase().replace(/^\*\./,'').replace(/\.$/,''); return !!root && (host===root || host.endsWith('.'+root)); }
function safeUrl(raw){ try { const u=new URL(raw); for(const [k] of u.searchParams) u.searchParams.set(k,'[REDACTED]'); u.hash=''; return u.toString(); } catch { return ''; } }
async function send(details,eventType,extra={}){
  const c=await cfg(); if(!c.enabled||!c.token||!c.scanId||!c.rootDomain)return;
  let u; try{u=new URL(details.url)}catch{return;}
  if(!['http:','https:'].includes(u.protocol)||!inScope(u.hostname,c.rootDomain))return;
  const payload={token:c.token,event_type:eventType,request_id:String(details.requestId),url:safeUrl(details.url),method:details.method||'GET',resource_type:details.type||'other',initiator:details.initiator||'',tab_id:details.tabId,timestamp:details.timeStamp||Date.now(),...extra};
  try{const r=await fetch(`${c.baseUrl.replace(/\/$/,'')}/api/scans/${encodeURIComponent(c.scanId)}/browser-capture`,{method:'POST',headers:{'Content-Type':'text/plain'},body:JSON.stringify(payload)});if(!r.ok){let msg=`HTTP ${r.status}`;try{const j=await r.json();msg=j.detail||msg;}catch{}await chrome.storage.local.set({lastError:msg,lastSuccessAt:0});chrome.action.setBadgeText({text:'ERR'});chrome.action.setBadgeBackgroundColor({color:'#b91c1c'});}else{await chrome.storage.local.set({lastError:'',lastSuccessAt:Date.now()});chrome.action.setBadgeText({text:'ON'});chrome.action.setBadgeBackgroundColor({color:'#15803d'});}}catch(e){await chrome.storage.local.set({lastError:String(e),lastSuccessAt:0});chrome.action.setBadgeText({text:'ERR'});chrome.action.setBadgeBackgroundColor({color:'#b91c1c'});}
}
chrome.webRequest.onBeforeRequest.addListener(d=>{
  const cPromise=cfg(); cPromise.then(c=>{let form=null;if(c.captureBodies&&d.requestBody?.formData){form={};for(const [k,v] of Object.entries(d.requestBody.formData))form[k]=v.map(x=>String(x).slice(0,1000));}send(d,'request-start',{form_data:form});});
},{urls:['<all_urls>']},['requestBody']);
chrome.webRequest.onBeforeSendHeaders.addListener(d=>{
  const headers=(d.requestHeaders||[]).filter(h=>!SENSITIVE.test(h.name)).map(h=>({name:h.name,value:String(h.value||'').slice(0,1000)}));
  send(d,'request-headers',{request_headers:headers});
},{urls:['<all_urls>']},['requestHeaders','extraHeaders']);
chrome.webRequest.onCompleted.addListener(d=>send(d,'request-complete',{status_code:d.statusCode}),{urls:['<all_urls>']});
chrome.webRequest.onErrorOccurred.addListener(d=>send(d,'request-error',{error:d.error||'network error'}),{urls:['<all_urls>']});
chrome.runtime.onMessage.addListener((msg,_sender,reply)=>{
  if(msg?.type==='toggle') cfg().then(c=>chrome.storage.local.set({enabled:!c.enabled})).then(async()=>{const c=await cfg();chrome.action.setBadgeText({text:c.enabled?'ON':''});reply({enabled:c.enabled});});
  if(msg?.type==='status') Promise.all([cfg(),chrome.storage.local.get({lastError:'',lastSuccessAt:0})]).then(([c,d])=>reply({enabled:c.enabled,configured:!!(c.baseUrl&&c.scanId&&c.rootDomain&&c.token),lastError:d.lastError,lastSuccessAt:d.lastSuccessAt,baseUrl:c.baseUrl,scanId:c.scanId}));
  return true;
});
