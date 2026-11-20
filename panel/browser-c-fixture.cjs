"use strict";
// Actual C HTTP executable with local files and a service recorder, never /opt or a router.
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),net=require('node:net');
const {spawn}=require('node:child_process');
module.exports=async function(visualFixture){
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'d2k-c-browser-'));
 const config=path.join(temp,'config'),live=path.join(temp,'live.json'),log=path.join(temp,'actions');
 const engine=path.join(temp,'engine.pid'),controller=path.join(temp,'controller.pid'),telegram=path.join(temp,'telegram.pid');
 const tgStatus=path.join(temp,'tg-status'),service=path.join(temp,'service');
 const pid=String(process.pid)+'\n';
 const writeLive=()=>fs.writeFileSync(live,JSON.stringify({...visualFixture.knowledge,linked:true,catalog_at:'local-browser-fixture'}));
 fs.writeFileSync(config,'MODE=apply\nTG_ENABLED=1\nTG_RELAY_URL=https://relay.example.invalid\nTG_RELAY_SECRET=public-test-fixture\n');
 for(const file of [engine,controller,telegram])fs.writeFileSync(file,pid);
 fs.writeFileSync(tgStatus,'connected\n');writeLive();
 fs.writeFileSync(service,'#!/usr/bin/env node\n'+
  'const fs=require("node:fs");const action=process.argv[2];\n'+
  'const paths='+JSON.stringify({config,log,engine,policyFail:path.join(temp,"policy-fail")})+';\n'+
  'if(action==="engine-stop")fs.rmSync(paths.engine,{force:true});\n'+
  'if(action==="engine-start"||action==="engine-restart")fs.writeFileSync(paths.engine,'+JSON.stringify(pid)+');\n'+
  'if(action.startsWith("telegram-"))fs.writeFileSync(paths.config,fs.readFileSync(paths.config,"utf8").replace(/TG_ENABLED=[01]/,"TG_ENABLED="+(action==="telegram-enable"?1:0)));\n'+
  'fs.appendFileSync(paths.log,action+"\\n");\n'+
  'if(action==="engine-restart"&&fs.existsSync(paths.policyFail))process.exit(1);\n',{mode:0o700});
 const socket=net.createServer();await new Promise(r=>socket.listen(0,'127.0.0.1',r));
 const port=socket.address().port;await new Promise(r=>socket.close(r));
 const ndmc=path.join(temp,'ndmc');
 fs.writeFileSync(ndmc,"#!/bin/sh\nprintf '%s\\n' 'policy, name = Policy7, description = Work <devices>:' ' mark: 00ab' 'policy, name = D2Ktest:' ' mark: ff'\n",{mode:0o700});
 const child=spawn(path.join(__dirname,'d2kpanel'),['serve','--config',config,'--listen','127.0.0.1:'+port,
  '--live',live,'--assets',path.resolve(__dirname,'../internal/web/assets'),'--service',service,
  '--engine-pid',engine,'--controller-pid',controller,'--telegram-pid',telegram,'--telegram-status',tgStatus],{stdio:'ignore',env:{...process.env,PATH:temp+path.delimiter+process.env.PATH}});
 const timer=setInterval(writeLive,2000),url='http://127.0.0.1:'+port+'/';
 const close=async()=>{
  clearInterval(timer);child.kill('SIGTERM');
  if(child.exitCode===null)await new Promise(r=>child.once('exit',r));
  fs.rmSync(temp,{recursive:true,force:true});
 };
 try {
  for(let i=0;i<50;i++){
   try {const r=await fetch(url+'api/status',{signal:AbortSignal.timeout(300)});if(r.ok)break;}catch{}
   if(child.exitCode!==null)throw Error('C panel exited before browser integration');
   await new Promise(r=>setTimeout(r,50));
  }
  const status=await(await fetch(url+'api/status')).json();
  if(!status.knowledge.linked)throw Error('Isolated C fixture is not linked');
  /* seen — проверка «команды НЕ было». waitFor для этого не годится: он
     ждёт появления и падает по тайм-ауту, то есть отрицание им стоит три
     секунды и читается как поломка. */
  return {url,close,policyFail:on=>{const file=path.join(temp,"policy-fail");if(on)fs.writeFileSync(file,"1");else fs.rmSync(file,{force:true});},policy:()=>{const match=fs.readFileSync(config,"utf8").match(/^KEENETIC_POLICY='([^']*)'/m);return match?match[1]:"";},telegram:status=>fs.writeFileSync(tgStatus,status+'\n'),
   seen:(command)=>fs.existsSync(log)&&fs.readFileSync(log,'utf8').split('\n').includes(command),
   waitFor:async(command)=>{
   for(let i=0;i<60;i++){
    if(fs.existsSync(log)&&fs.readFileSync(log,'utf8').split('\n').includes(command))return;
    await new Promise(r=>setTimeout(r,50));
   }
   throw Error('Service did not receive '+command);
  }};
 }catch(error){await close();throw error;}
};
