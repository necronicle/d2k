import {strict as assert} from 'node:assert';
import {test} from 'node:test';
import {collectPlayback} from './videoobserve.mjs';

const EPOCH=1795074544902;
function fixture(states) {
  let now=EPOCH,index=0;
  const page={call:async(method)=>{
    assert.equal(method,'Runtime.evaluate');
    const state=states[Math.min(index++,states.length-1)];
    return {result:{value:JSON.stringify(state)}};
  }};
  return {page,now:()=>now,sleep:async ms=>{now+=ms;}};
}
const state=(currentTime,extra={})=>({currentTime,readyState:4,paused:false,ended:false,waiting:false,...extra});

test('navigation destroys an execution context without inventing playback across it',async()=>{
  let now=EPOCH,calls=0;
  const page={call:async()=>{
    if(++calls===2)throw Error('Inspected target navigated or closed');
    return {result:{value:JSON.stringify(state(calls/10))}};
  }};
  const r=await collectPlayback(page,{durationMs:250,startupTimeoutMs:1000,intervalMs:250,
    now:()=>now,sleep:async ms=>{now+=ms;}});
  assert.equal(r.samples.length,3);
  assert.equal(r.endedAt,EPOCH+750);
});

test('observation starts at the real first frame and stops after the requested progressing playback',async()=>{
  const f=fixture([state(0),state(0.1),state(0.2),state(0.3),state(0.4)]);
  const r=await collectPlayback(f.page,{durationMs:500,startupTimeoutMs:1000,intervalMs:250,now:f.now,sleep:f.sleep});
  assert.equal(r.startedAt,EPOCH);assert.equal(r.startedPlaybackAt,EPOCH+250);assert.equal(r.endedAt,EPOCH+750);
  assert.deepEqual(r.samples.map(s=>s.at),[EPOCH,EPOCH+250,EPOCH+500,EPOCH+750]);
  assert.deepEqual(r.samples.map(s=>s.currentTime),[0,0.1,0.2,0.3]);
});

test('missing video produces no invented samples and reaches its bounded deadline',async()=>{
  const f=fixture([null]);
  const r=await collectPlayback(f.page,{durationMs:500,startupTimeoutMs:500,intervalMs:250,now:f.now,sleep:f.sleep});
  assert.deepEqual(r.samples,[]);assert.equal(r.startedPlaybackAt,null);assert.equal(r.endedAt,EPOCH+500);
});

test('observed waiting and stalled states reach the real playback samples',async()=>{
  const f=fixture([state(0.1),state(0.1,{waiting:true}),state(0.1,{stalled:true}),state(0.2)]);
  const r=await collectPlayback(f.page,{durationMs:250,startupTimeoutMs:1000,intervalMs:250,now:f.now,sleep:f.sleep});
  assert.equal(r.samples[1].waiting,true);assert.equal(r.samples[2].stalled,true);
});
