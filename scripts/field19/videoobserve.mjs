import {mkdirSync,readFileSync,writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
import {summarizeVideo,VIDEO_INSTRUMENT_VERSION} from './video-metrics.mjs';

function progressing(sample) {
  return sample && sample.currentTime>0 && sample.readyState>=3 &&
    !sample.paused && !sample.ended && !sample.waiting && !sample.stalled;
}

export async function collectPlayback(page,{durationMs=60000,startupTimeoutMs=120000,intervalMs=250,
    now=Date.now,sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}) {
  if(!Number.isFinite(durationMs)||durationMs<=0||!Number.isFinite(startupTimeoutMs)||startupTimeoutMs<0||
      !Number.isFinite(intervalMs)||intervalMs<=0)throw Error('invalid playback observation timing');
  const startedAt=now(),samples=[];
  let startedPlaybackAt=null,activeMs=0,previous=null,endedAt=startedAt;
  const maximumMs=durationMs+startupTimeoutMs;
  for(;;) {
    const at=now(),elapsed=at-startedAt;
    let response;
    try {response=await page.call('Runtime.evaluate',{
      expression:`JSON.stringify((()=>{const v=document.querySelector('video.html5_main_video')||document.querySelector('video');if(!v)return null;return {currentTime:v.currentTime,readyState:v.readyState,paused:v.paused,ended:v.ended,waiting:Boolean(v.__d2kWaiting),stalled:Boolean(v.__d2kStalled)};})())`,
      returnByValue:true
    });} catch(error) {
      if(!/context.*destroyed|Cannot find context|Inspected target navigated|Runtime.evaluate timeout/i.test(String(error)))throw error;
      previous=null;endedAt=now();
      if(endedAt-startedAt>=maximumMs)break;
      await sleep(intervalMs);continue;
    }
    const value=JSON.parse(response.result?.value||'null');
    if(value && Number.isFinite(value.currentTime)) {
      const sample={at,...value};samples.push(sample);
      if(startedPlaybackAt===null&&sample.currentTime>0)startedPlaybackAt=at;
      if(previous&&progressing(previous)&&sample.currentTime>previous.currentTime)
        activeMs+=Math.max(0,at-previous.at);
      previous=sample;
    }
    endedAt=now();
    if(activeMs>=durationMs||elapsed>=maximumMs)break;
    if(startedPlaybackAt===null&&elapsed>=startupTimeoutMs) {
      endedAt=now();break;
    }
    const remaining=startedPlaybackAt===null?startupTimeoutMs-elapsed:maximumMs-elapsed;
    await sleep(Math.max(1,Math.min(intervalMs,remaining)));
  }
  return {startedAt,startedPlaybackAt,endedAt,samples};
}

async function rpc(url,event=()=>{}) {
  const ws=new WebSocket(url);let seq=0;const pending=new Map();
  await new Promise((resolve,reject)=>{ws.onopen=resolve;ws.onerror=reject;});
  ws.onmessage=e=>{
    const message=JSON.parse(e.data);
    if(message.id&&pending.has(message.id)) {
      const {resolve,reject,timer}=pending.get(message.id);clearTimeout(timer);pending.delete(message.id);
      message.error?reject(Error(JSON.stringify(message.error))):resolve(message.result);
    } else event(message);
  };
  return {
    close:()=>ws.close(),
    call:(method,params={})=>new Promise((resolve,reject)=>{
      const id=++seq;
      const timer=setTimeout(()=>{pending.delete(id);reject(Error(`${method} timeout`));},15000);
      pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}));
    })
  };
}

export const ARM_VIDEO_EXPRESSION=`new Promise(resolve=>{let done=false,observer=null,timer=null;const arm=v=>{if(done)return;done=true;if(timer)clearTimeout(timer);if(observer)observer.disconnect();v.__d2kWaiting=false;v.__d2kStalled=false;v.addEventListener('waiting',()=>v.__d2kWaiting=true);v.addEventListener('stalled',()=>v.__d2kStalled=true);v.addEventListener('playing',()=>{v.__d2kWaiting=false;v.__d2kStalled=false;});v.play().then(()=>resolve(true)).catch(()=>resolve(false));};const find=()=>document.querySelector('video.html5_main_video')||document.querySelector('video');timer=setTimeout(()=>{if(!done){done=true;if(observer)observer.disconnect();resolve(false);}},5000);const v=find();if(v){arm(v);return;}observer=new MutationObserver(()=>{const next=find();if(next)arm(next);});observer.observe(document.documentElement,{childList:true,subtree:true});})`;

async function main() {
  const [port,out,input,durationArg='60']=process.argv.slice(2);
  if(!port||!out||!input||Number(durationArg)!==60)throw Error('usage: videoobserve.mjs PORT OUT URL_JSON 60');
  const spec=JSON.parse(readFileSync(input,'utf8'));
  if(!spec||!/^[\w.-]+$/.test(spec.id)||typeof spec.url!=='string'||!spec.url.startsWith('https://'))
    throw Error('private video input must contain a safe id and an https URL');
  mkdirSync(out,{recursive:true});
  const durationSeconds=60,durationMs=durationSeconds*1000,startupTimeoutMs=120000;
  const watchdog=setTimeout(()=>process.exit(1),(durationMs+startupTimeoutMs+120000));
  let browser,page,targetId;const requests=new Map(),observerErrors=[];
  try {
    let version;
    for(let i=0;i<50;i++) {
      try {version=await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();break;}
      catch(error) {if(i===49)throw error;await new Promise(resolve=>setTimeout(resolve,200));}
    }
    browser=await rpc(version.webSocketDebuggerUrl);
    ({targetId}=await browser.call('Target.createTarget',{url:'about:blank'}));
    const tabs=await (await fetch(`http://127.0.0.1:${port}/json`)).json();
    const tab=tabs.find(t=>t.id===targetId);if(!tab)throw Error('created target not found');
    page=await rpc(tab.webSocketDebuggerUrl,message=>{
      const p=message.params||{},id=p.requestId;
      if(message.method==='Network.requestWillBeSent') {
        requests.set(id,{url:p.request.url,method:p.request.method,type:p.type,start:p.timestamp,
          range:p.request.headers?.Range||p.request.headers?.range||null});
      }
      const request=requests.get(id);if(!request)return;
      if(message.method==='Network.responseReceived') {
        request.status=p.response.status;request.mime=p.response.mimeType;request.protocol=p.response.protocol;
        request.ip=p.response.remoteIPAddress;
        request.responseRange=p.response.headers?.['Content-Range']||p.response.headers?.['content-range']||null;
      }
      if(message.method==='Network.loadingFinished'){request.finished=true;request.end=p.timestamp;}
      if(message.method==='Network.loadingFailed'){request.finished=false;request.error=p.errorText;request.end=p.timestamp;}
    });
    await page.call('Network.enable');await page.call('Network.setCacheDisabled',{cacheDisabled:true});
    await page.call('Page.enable');await page.call('Runtime.enable');
    await page.call('Page.addScriptToEvaluateOnNewDocument',{source:ARM_VIDEO_EXPRESSION});
    try {await page.call('Page.navigate',{url:spec.url});}
    catch(error) {if(!/Page.navigate timeout/.test(String(error)))throw error;observerErrors.push(String(error));}
    const collecting=collectPlayback(page,{durationMs,startupTimeoutMs});
    await page.call('Runtime.evaluate',{
      expression:ARM_VIDEO_EXPRESSION,
      awaitPromise:true,userGesture:true,returnByValue:true
    }).catch(error=>{observerErrors.push(String(error));});
    const collected=await collecting;
    const rawRequests=[...requests.values()];
    const verdict=summarizeVideo({...collected,requests:rawRequests});
    writeFileSync(`${out}/network.private.json`,JSON.stringify(rawRequests,null,2),{mode:0o600});
    writeFileSync(`${out}/playback.private.json`,JSON.stringify({...collected,observerErrors},null,2),{mode:0o600});
    writeFileSync(`${out}/summary.json`,JSON.stringify({videoId:spec.id,...verdict},null,2));
    const manifest={videoId:spec.id,instrumentVersion:VIDEO_INSTRUMENT_VERSION,durationSeconds,verdict};
    writeFileSync(`${out}/manifest.json`,JSON.stringify(manifest,null,2));
    console.log(JSON.stringify({videoId:spec.id,...verdict}));
    if(!verdict.passed)process.exitCode=1;
  } catch(error) {
    observerErrors.push(String(error));
    writeFileSync(`${out}/network.private.json`,JSON.stringify([...requests.values()],null,2),{mode:0o600});
    writeFileSync(`${out}/observer.private.json`,JSON.stringify({errors:observerErrors},null,2),{mode:0o600});
    const verdict={passed:false,playback_seconds:0,completed_media:0,startup_ms:null,rebuffer_events:0,rebuffer_ms:0,failures:['observer_error']};
    writeFileSync(`${out}/summary.json`,JSON.stringify({videoId:spec.id,...verdict},null,2));
    writeFileSync(`${out}/manifest.json`,JSON.stringify({videoId:spec.id,instrumentVersion:VIDEO_INSTRUMENT_VERSION,durationSeconds,verdict},null,2));
    console.error('video observation failed');process.exitCode=1;
  } finally {
    if(targetId&&browser)await browser.call('Target.closeTarget',{targetId}).catch(()=>{});
    if(page)page.close();if(browser){await browser.call('Browser.close').catch(()=>{});browser.close();}
    clearTimeout(watchdog);
  }
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)await main();
