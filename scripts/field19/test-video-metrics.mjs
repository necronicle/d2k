import {strict as assert} from 'node:assert';
import {test} from 'node:test';
import {summarizeVideo,compareRuns} from './video-metrics.mjs';

const media=(finished=true)=>({type:'Media',mime:'video/mp4',status:206,finished,range:'bytes=0-999',responseRange:'bytes 0-999/10000'});
const playing=(at,currentTime)=>({at,currentTime,readyState:4,paused:false,ended:false,waiting:false});
function run(overrides={}) {
  return {startedAt:0,startedPlaybackAt:1000,endedAt:61000,
    samples:[playing(1000,0.1),playing(61000,60.1)],requests:[media(),media()],...overrides};
}
function manifest(overrides={}) {
  return {videoId:'video-a',instrumentVersion:'1',durationSeconds:60,
    verdict:{passed:true,playback_seconds:60,completed_media:2,startup_ms:1000,rebuffer_events:0,rebuffer_ms:0},...overrides};
}

test('accepts 60 seconds of progressing playback and two completed media responses',()=>{
  const v=summarizeVideo(run());
  assert.equal(v.passed,true);assert.equal(v.playback_seconds,60);
  assert.equal(v.completed_media,2);assert.equal(v.startup_ms,1000);
  assert.deepEqual(v.failures,[]);
});

test('rejects 59.999 seconds even when media responses completed',()=>{
  const v=summarizeVideo(run({endedAt:60999,samples:[playing(1000,0.1),playing(60999,60.099)]}));
  assert.equal(v.passed,false);assert.equal(v.playback_seconds,59.999);
  assert.ok(v.failures.includes('playback_under_60s'));
});

test('counts completed UMP media responses but not telemetry or failed UMP loads',()=>{
  const ump={type:'Fetch',mime:'application/vnd.yt-ump',status:200,finished:true};
  const v=summarizeVideo(run({requests:[ump,ump,{...ump,finished:false},
    {...ump,mime:'text/plain',status:204},{...ump,status:500}]}));
  assert.equal(v.completed_media,2);assert.equal(v.passed,true);
});

test('rejects a single completed media response and does not count failed loads',()=>{
  const v=summarizeVideo(run({requests:[media(),media(false)]}));
  assert.equal(v.completed_media,1);assert.equal(v.passed,false);
  assert.ok(v.failures.includes('media_under_2'));
});

test('counts waiting time only after playback started',()=>{
  const v=summarizeVideo(run({endedAt:64000,samples:[
    playing(1000,0.1),playing(10000,9),{...playing(11000,9),waiting:true},
    {...playing(13000,9),readyState:2},playing(14000,10),playing(64000,60)
  ]}));
  assert.equal(v.rebuffer_events,1);assert.equal(v.rebuffer_ms,3000);
});

test('does not turn initial buffering into playback or startup rebuffering',()=>{
  const v=summarizeVideo(run({startedPlaybackAt:6000,samples:[
    {...playing(0,0),waiting:true},{...playing(5000,0),readyState:2},playing(6000,0.1),playing(66000,60.1)
  ],endedAt:66000}));
  assert.equal(v.startup_ms,6000);assert.equal(v.rebuffer_events,0);
  assert.equal(v.rebuffer_ms,0);assert.equal(v.playback_seconds,60);
});

test('missing video samples are an observation failure',()=>{
  const v=summarizeVideo(run({samples:[]}));
  assert.equal(v.passed,false);assert.ok(v.failures.includes('no_playback_samples'));
});

test('sanitized verdict cannot leak signed media URLs or tokens',()=>{
  const v=summarizeVideo(run({requests:[{...media(),url:'https://media.invalid/videoplayback?sig=TOPSECRET',headers:{Authorization:'Bearer TOPSECRET'}}]}));
  const text=JSON.stringify(v);
  assert.equal(text.includes('TOPSECRET'),false);assert.equal(text.includes('videoplayback'),false);
  assert.equal(text.includes('https://'),false);
});

test('comparison rejects different videos, instrument versions, and durations',()=>{
  for(const [key,value] of [['videoId','video-b'],['instrumentVersion','2'],['durationSeconds',59]]) {
    const c=compareRuns(manifest(),manifest({[key]:value}));
    assert.equal(c.valid,false,key);assert.equal(c.passed,false,key);
  }
});

test('comparison accepts equal or better startup and rebuffering',()=>{
  const c=compareRuns(manifest(),manifest({verdict:{passed:true,playback_seconds:60,completed_media:2,startup_ms:800,rebuffer_events:0,rebuffer_ms:0}}));
  assert.deepEqual(c,{valid:true,passed:true,failures:[]});
});

test('comparison rejects worse startup, rebuffering, or a failed candidate',()=>{
  for(const override of [{startup_ms:1001},{rebuffer_ms:1},{rebuffer_events:1},{passed:false}]) {
    const candidate=manifest();candidate.verdict={...candidate.verdict,...override};
    const c=compareRuns(manifest(),candidate);assert.equal(c.valid,true);assert.equal(c.passed,false);
  }
});

test('real epoch timestamps keep startup and unfinished rebuffer durations bounded',()=>{
  const base=1795074544902;
  const v=summarizeVideo({startedAt:base,startedPlaybackAt:null,endedAt:base+65000,samples:[
    playing(base,0),playing(base+5000,0.1),playing(base+10000,1),{...playing(base+11000,1),waiting:true}
  ],requests:[media(),media()]});
  assert.equal(v.startup_ms,5000);assert.equal(v.rebuffer_ms,54000);
});

test('stalled samples neither advance playback nor disappear from rebuffer metrics',()=>{
  const v=summarizeVideo(run({endedAt:64000,samples:[
    playing(1000,0.1),playing(10000,9),{...playing(11000,9),stalled:true},playing(14000,10),playing(64000,60)
  ]}));
  assert.equal(v.rebuffer_events,1);assert.equal(v.rebuffer_ms,3000);
});

test('HTTP errors, missing responses, and invalid range replies are not completed media',()=>{
  for(const request of [
    {...media(),status:404},{...media(),status:416},
    {type:'Media',mime:'video/mp4',finished:true,range:'bytes=0-999',responseRange:'bytes 0-999/10000'},
    {...media(),status:200},{...media(),responseRange:null}
  ]) {
    const v=summarizeVideo(run({requests:[request]}));
    assert.equal(v.completed_media,0);assert.equal(v.passed,false);
  }
});
