"""Actual C serializer contract, not a reimplementation of its output."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
with tempfile.TemporaryDirectory() as directory:
    dest = Path(directory) / 'report.json'
    subprocess.run([str(Path(__file__).resolve().parent / 'test_diagnostics')],
                   env=dict(os.environ, D2K_TEST_DIAG_JSON=str(dest)), check=True)
    report = json.loads(dest.read_text())
    assert report['schema'] == 1 and report['enabled'] is True
    assert report['ring_bytes'] <= 128 * 1024
    sample = report['samples'][0]
    assert sample['mem_total_kib'] == 65536
    assert sample['processes'][0]['rss_kib'] == 1024
    assert sample['processes'][1]['rss_kib'] is None
    assert sample['datapath_flows'] is None
    assert sample['system_conntrack'] is None
    # Экспортируемый экземпляр событий поиска не содержит (он создан для
    # снимков памяти), поэтому КОНТРАКТ СОБЫТИЯ проверяет сам C-тест по той
    # же строке JSON: outcome_reason, plan_id и box_id рядом с reason. Здесь
    # сторожим лишь то, что ключ событий из файла не исчез.
    assert isinstance(report['events'], list)
print('diagnostics JSON: real serializer PASS')

details = report['memory_details'][0]
assert details['name'] == 'd2kc'
assert details['first']['mono_ms'] == 0
assert details['first']['rss_kib'] == 1024
assert details['latest']['mono_ms'] == 60000
assert details['latest']['rss_kib'] == 4096
assert details['latest']['vm_size_kib'] == 8192
assert details['latest']['smaps']['heap']['rss_kib'] == 8
assert details['latest']['smaps']['anonymous']['rss_kib'] == 24
assert details['latest']['smaps']['other']['rss_kib'] == 4
assert details['latest']['fd_count'] is None
assert report['memory_details'][1]['latest'] is None
assert 'never-export-me' not in json.dumps(report)
print('memory detail snapshot contract PASS')

# Additive schema 1: legacy readers can ignore new fields; our contract
# validator accepts old snapshots without them and checks types when present.
def validate_memory_details(data):
    for detail in data.get('memory_details', []):
        for which in ('first', 'latest'):
            snapshot = detail.get(which)
            if snapshot is None:
                continue
            for key in ('rss_kib', 'anon_kib', 'start_ticks'):
                value = snapshot.get(key)
                assert value is None or (type(value) is int and value >= 0)
            owners = snapshot.get('owners')
            if owners is not None:
                assert all(type(v) is int and v >= 0 for v in owners.values())

validate_memory_details(report)
legacy = json.loads(json.dumps(report))
for item in legacy['memory_details']:
    for which in ('first', 'latest'):
        if item[which]:
            item[which].pop('owners', None)
            item[which].pop('anon_kib', None)
validate_memory_details(legacy)
first, latest = details['first'], details['latest']
assert first['anon_kib'] == 512 and latest['anon_kib'] == 3072
assert first['start_ticks'] == latest['start_ticks'] == 54321
assert first['owners']['workers_started'] == 7
assert first['owners']['worker_args_live_bytes'] == 9000
assert latest['owners']['workers_started'] == latest['owners']['workers_joined'] == 9
assert latest['owners']['worker_args_live_bytes'] == 0
expected = dict(worker_join_errors=0, worker_start_while_live=0, worker_args_allocated=9, worker_args_freed=9,
                worker_args_live=0, http_records_capacity=16, http_records_bytes=24000,
                http_queue_capacity=8, http_queue_bytes=2200, http_failures=3,
                http_failures_bytes=600, task_madvise_calls=11, task_madvise_successes=10,
                task_madvise_requested_bytes=45056, task_madvise_last_errno=12,
                catalog_boxes_bytes=4096, catalog_plans_bytes=1024, catalog_bindings_bytes=8192)
for key, value in expected.items():
    assert latest['owners'][key] == value, key
assert len(latest['owners']) == 21
assert report['samples'][0]['processes'][0]['start_ticks'] == 54321
assert report['samples'][1]['processes'][0]['start_ticks'] == 54321
assert report['samples'][0]['processes'][0]['pid'] == report['controller_pid']
assert 'owners' not in (report['memory_details'][1]['latest'] or {})
print('memory owners, self identity and old JSON compatibility PASS')
