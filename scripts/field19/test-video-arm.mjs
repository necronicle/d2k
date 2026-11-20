import {strict as assert} from 'node:assert';
import {test} from 'node:test';
import {ARM_VIDEO_EXPRESSION} from './videoobserve.mjs';

test('arm expression can start an already present video without a MutationObserver temporal-dead-zone error',async()=>{
  const video={addEventListener(){},play:()=>Promise.resolve(true)};
  const document={querySelector:()=>video,documentElement:{}};
  class MutationObserver {constructor(){} observe(){} disconnect(){}}
  const evaluate=new Function('document','MutationObserver',`return ${ARM_VIDEO_EXPRESSION}`);
  assert.equal(await evaluate(document,MutationObserver),true);
});
