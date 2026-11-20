import {strict as assert} from 'node:assert';
import {test} from 'node:test';
import {compareRuns} from './video-metrics.mjs';

const verdict=passed=>({passed,playback_seconds:passed?60:0,completed_media:passed?2:0,startup_ms:passed?1000:null,rebuffer_events:0,rebuffer_ms:0});
const manifest=passed=>({videoId:'video-a',instrumentVersion:'1',durationSeconds:60,verdict:verdict(passed)});

test('a working candidate is an improvement when the same baseline video cannot play',()=>{
  const c=compareRuns(manifest(false),manifest(true));
  assert.deepEqual(c,{valid:true,passed:true,failures:[]});
});

test('neither side playing remains a failed comparison',()=>{
  const c=compareRuns(manifest(false),manifest(false));
  assert.equal(c.valid,true);assert.equal(c.passed,false);
  assert.ok(c.failures.includes('candidate_failed'));
});
