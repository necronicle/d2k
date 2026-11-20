export const VIDEO_INSTRUMENT_VERSION='2';

function playing(sample) {
  return sample && Number.isFinite(sample.at) && Number.isFinite(sample.currentTime) &&
    sample.currentTime>0 && sample.readyState>=3 && !sample.paused && !sample.ended &&
    !sample.waiting && !sample.stalled;
}
function mediaRequest(request) {
  if(!request || !request.finished || !Number.isInteger(request.status) ||
      request.status<200 || request.status>=300)return false;
  if((request.range||request.responseRange) &&
      (request.status!==206 || !request.responseRange))return false;
  return request.type==='Media' || /^(video|audio)\//.test(request.mime||'') ||
    request.mime==='application/vnd.yt-ump' ||
    request.range || request.responseRange;
}
function rounded(value) {
  return Math.round(value*1000)/1000;
}

export function summarizeVideo({startedAt,startedPlaybackAt,endedAt,samples=[],requests=[]}) {
  const ordered=samples.filter(s=>Number.isFinite(s?.at)).slice().sort((a,b)=>a.at-b.at);
  const first=ordered.find(s=>Number.isFinite(s.currentTime)&&s.currentTime>0);
  const failures=[];
  let playbackMs=0,rebufferMs=0,rebufferEvents=0,rebufferAt=null;
  if(first) {
    for(let i=0;i<ordered.length;i++) {
      const a=ordered[i],b=ordered[i+1];
      if(a.at<first.at)continue;
      if(b && playing(a) && Number.isFinite(b.currentTime) && b.currentTime>a.currentTime)
        playbackMs+=Math.max(0,b.at-a.at);
      if(!rebufferAt && a.at>first.at && (a.waiting || a.stalled || (!a.ended && a.readyState<3))) {
        rebufferAt=a.at;rebufferEvents++;
      }
      if(rebufferAt && playing(a) && a.at>rebufferAt) {
        rebufferMs+=a.at-rebufferAt;rebufferAt=null;
      }
    }
    if(rebufferAt && Number.isFinite(endedAt))rebufferMs+=Math.max(0,endedAt-rebufferAt);
  } else failures.push('no_playback_samples');
  const completed=requests.filter(mediaRequest).length;
  const playbackSeconds=rounded(playbackMs/1000);
  if(playbackSeconds<60)failures.push('playback_under_60s');
  if(completed<2)failures.push('media_under_2');
  const startup=first?.at??startedPlaybackAt;
  return {
    passed:failures.length===0,
    playback_seconds:playbackSeconds,
    completed_media:completed,
    startup_ms:Number.isFinite(startup)&&Number.isFinite(startedAt)?Math.max(0,startup-startedAt):null,
    rebuffer_events:rebufferEvents,
    rebuffer_ms:rebufferMs,
    failures
  };
}

export function compareRuns(baseline,candidate) {
  if(!baseline||!candidate||baseline.videoId!==candidate.videoId)
    return {valid:false,passed:false,failures:['different_video']};
  if(baseline.instrumentVersion!==candidate.instrumentVersion)
    return {valid:false,passed:false,failures:['different_instrument']};
  if(baseline.durationSeconds!==60||candidate.durationSeconds!==60)
    return {valid:false,passed:false,failures:['different_duration']};
  const a=baseline.verdict,b=candidate.verdict;
  if(!a||!b)return {valid:false,passed:false,failures:['missing_verdict']};
  const failures=[];
  if(!b.passed)failures.push('candidate_failed');
  if(a.passed) {
    if(b.startup_ms>a.startup_ms)failures.push('startup_worse');
    if(b.rebuffer_ms>a.rebuffer_ms)failures.push('rebuffer_ms_worse');
    if(b.rebuffer_events>a.rebuffer_events)failures.push('rebuffer_events_worse');
  }
  return {valid:true,passed:failures.length===0,failures};
}
