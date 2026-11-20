'use strict';
// Deliberately no localStorage, cookies, analytics, external assets or eval.
let bearer = '';
let current = 'overview';
const cursors = Object.create(null);
const titles = {overview:'Overview', events:'Telemetry',detections:'Detections',incidents:'Incidents',responses:'Response proposals'};
const $ = id => document.getElementById(id);
function text(element,value){element.textContent = value == null ? '—' : String(value);return element;}
function element(tag, value, className){const el=document.createElement(tag);if(value!==undefined) text(el,value);if(className)el.className=className;return el;}
function notice(s){text($('notice'),s);}
async function api(path,{method='GET',body,token=bearer}={}){
  if(!token)throw new Error('Connect using your operator token first.');
  const resp=await fetch(path,{method,cache:'no-store',credentials:'omit',signal:AbortSignal.timeout(12000),headers:{Authorization:`Bearer ${token}`,...(body?{'Content-Type':'application/json'}:{})},body:body?JSON.stringify(body):undefined});
  let payload;const raw=await resp.text();try{payload=JSON.parse(raw)}catch{payload=raw}
  if(!resp.ok)throw new Error(`${resp.status}: ${payload?.error||'Request failed'}`);
  return payload;
}
function safeDate(sec){return typeof sec==='number'&&sec>0?new Date(sec*1000).toLocaleString():'—'}
function metric(raw,key){const re=new RegExp('^'+key.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')+'\\s+(-?\\d+)','m');const m=raw.match(re);return m?Number(m[1]):null}
function td(value,cls){return element('td',value==null?'—':value,cls)}
function renderTable(id,columns,rows,buttonCell){const host=$(id);host.replaceChildren();if(!rows.length){host.append(element('p','No records yet.','muted'));return}
  const table=document.createElement('table'),head=document.createElement('thead'),body=document.createElement('tbody'),tr=document.createElement('tr');
  for(const title of [...columns.map(c=>c[0]),...(buttonCell?['Action']:[])]){const cell=element('th',title);cell.scope='col';tr.append(cell)}head.append(tr);
  for(const row of rows){const tr=document.createElement('tr');for(const [_,key,formatter] of columns)tr.append(td(formatter?formatter(row[key],row):row[key],key==='id'||key==='event_id'?'mono':undefined));if(buttonCell){const cell=document.createElement('td');buttonCell(cell,row);tr.append(cell)}body.append(tr)}
  table.append(head,body);host.append(table);
}
function entry(title,detail,status,cls){const div=element('div',undefined,'entry'),inner=document.createElement('div');inner.append(element('strong',title),element('small',detail));div.append(inner,element('span',status,`state ${cls||''}`));return div}
async function loadOverview(){const [metrics,sources,incidents]=await Promise.all([api('/api/v1/metrics'),api('/api/v1/sources'),api('/api/v1/incidents?limit=10')]);
  text($('total-events'),metric(metrics,'sentinel_security_events')?.toLocaleString()??'—');text($('total-detections'),metric(metrics,'sentinel_detections')?.toLocaleString()??'—');text($('total-incidents'),metric(metrics,'sentinel_open_incidents')?.toLocaleString()??'—');
  const age=metric(metrics,'sentinel_last_ingest_age_seconds');text($('ingest-age'),age==null||age<0?'No data':age<60?`${age}s`:`${Math.floor(age/60)}m`);
  const incidentHost=$('overview-incidents');incidentHost.replaceChildren();for(const x of (incidents.items||[]))incidentHost.append(entry(x.title||x.subject_value,`${x.subject_value} · ${safeDate(x.last_seen_epoch)}`,x.severity,x.severity));
  if(!incidentHost.childElementCount)incidentHost.append(element('p','No incidents.','muted'));
  const healthHost=$('source-health');healthHost.replaceChildren();for(const x of sources)healthHost.append(entry(x.source,`Failures: ${x.consecutive_failures} · ${x.last_success||'No successful poll'}`,x.status,x.status==='ok'?'ok':'error'));
  if(!healthHost.childElementCount)healthHost.append(element('p','No source health reported.','muted'));
}
const configs={events:{path:'/api/v1/security-events',host:'events-table',columns:[['Time','event_ts'],['Source','source'],['Category','category'],['Action','action'],['Source IP','source_ip'],['Destination IP','destination_ip'],['Event ID','event_id']]},detections:{path:'/api/v1/detections',host:'detections-table',columns:[['Rule','rule_id'],['Severity','severity'],['Entity','entity_value'],['Observed','observed_count'],['Last seen','last_seen_epoch',safeDate],['Title','title']]},incidents:{path:'/api/v1/incidents',host:'incidents-table',columns:[['Severity','severity'],['Subject','subject_value'],['Title','title'],['Detections','detection_count'],['Last seen','last_seen_epoch',safeDate],['Status','status']]},responses:{path:'/api/v1/response/proposals',host:'responses-table',columns:[['Target','target_ip'],['Status','status'],['Requester','requester'],['Duration (min)','duration_minutes'],['Created','created_epoch',safeDate],['ID','id']]}};
async function loadPage(tab,older=false){const c=configs[tab];if(!older)cursors[tab]=null;const cursor=cursors[tab];const resp=await api(c.path+'?limit=30'+(cursor?'&before='+encodeURIComponent(cursor):''));const rows=resp.items??resp.events??[];
  if(tab==='responses')renderTable(c.host,c.columns,rows,(cell,r)=>{if(r.status==='proposed'){for(const kind of ['approve','reject']){const btn=element('button',kind,kind==='reject'?'secondary':'');btn.type='button';btn.addEventListener('click',()=>openDecision(kind,r));cell.append(btn,document.createTextNode(' '));}}});
  else renderTable(c.host,c.columns,rows);
  cursors[tab]=resp.next_cursor??null;const btn=document.querySelector(`[data-next="${tab}"]`);if(btn)btn.disabled=!cursors[tab];
}
async function load(){
  if(!bearer)return;
  const view=current, panel=$(view+'-panel');
  if(panel.getAttribute('aria-busy')==='true')return;
  panel.setAttribute('aria-busy','true');
  notice('Loading…');
  try{
    if(view==='overview')await loadOverview();else await loadPage(view);
    if(current===view)notice('');
  }catch(error){
    if(current===view)notice('Load failed: '+error.message);
  }finally{
    panel.removeAttribute('aria-busy');
  }
}
function tab(name){if(!titles[name])return;current=name;text($('page-title'),titles[name]);for(const b of document.querySelectorAll('[data-tab]')){const active=b.dataset.tab===name;b.classList.toggle('active',active);if(active)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');}for(const panel of document.querySelectorAll('.view'))panel.hidden=panel.id!==`${name}-panel`;void load()}
let decisionTarget=null;
function openDecision(kind,row){
  decisionTarget={kind,id:row.id};
  text($('decision-title'),kind==='approve'?'Approve proposal':'Reject proposal');
  text($('decision-description'),`${row.target_ip} · Requester ${row.requester}`);
  $('decision-form').reset();
  text($('decision-error'),'');
  $('decision-dialog').showModal();
}
$('decision-dialog').addEventListener('close',()=>{
  decisionTarget=null;
  $('decision-form').reset();
});
$('decision-cancel').addEventListener('click',()=>$('decision-dialog').close());
$('decision-form').addEventListener('submit',async e=>{
  e.preventDefault();
  if(!decisionTarget)return;
  const {kind,id}=decisionTarget;
  const token=$('decision-token').value.trim();
  const button=$('decision-confirm');
  text($('decision-error'),'');
  button.disabled=true;
  try{
    const decision=kind==='approve'?'approved':'rejected';
    await api(`/api/v1/response/proposals/${encodeURIComponent(id)}/${kind}`,{
      method:'POST',token,body:{
        actor:$('decision-actor').value.trim(),
        reason:$('decision-reason').value.trim(),
        confirm:`${decision.toUpperCase()} ${id}`,
      },
    });
    $('decision-dialog').close();
    await load();
    notice('Proposal '+decision+'.');
  }catch(error){
    text($('decision-error'),error.message);
  }finally{
    button.disabled=false;
  }
});
$('response-form').addEventListener('submit',async e=>{e.preventDefault();try{await api('/api/v1/response/proposals',{method:'POST',body:{target_ip:$('response-target').value.trim(),evidence_event_id:$('response-evidence').value.trim(),requester:$('response-requester').value.trim(),justification:$('response-reason').value.trim(),duration_minutes:Number($('response-duration').value)}});$('response-form').reset();await load();notice('Proposal recorded. Requires approval and separate simulated execution.')}catch(err){notice(err.message)}});
$('connect-form').addEventListener('submit',async e=>{e.preventDefault();const entered=$('api-token').value.trim();try{await api('/api/v1/sources',{token:entered});bearer=entered;$('api-token').value='';$('access').hidden=true;$('workspace').hidden=false;$('connection-dot').classList.add('connected');text($('connection-label'),'Connected locally');await load()}catch(err){notice(`Authentication failed: ${err.message}`)}});
for(const btn of document.querySelectorAll('[data-tab]'))btn.addEventListener('click',()=>tab(btn.dataset.tab));
for(const btn of document.querySelectorAll('[data-next]'))btn.addEventListener('click',async()=>{try{await loadPage(btn.dataset.next,true)}catch(e){notice(e.message)}});
$('refresh').addEventListener('click',()=>void load());
