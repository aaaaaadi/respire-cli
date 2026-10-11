"""Verify fixture deadlines fail explicitly and reap their owned inspector."""
import argparse
import ast
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import types

from native_fixture_process import captured_run

parser = argparse.ArgumentParser()
parser.add_argument('--output-dir', required=True)
args = parser.parse_args()
output = pathlib.Path(args.output_dir).resolve()
output.mkdir(parents=True, exist_ok=False)
results = []
# Exercise the actual sampler without starting a runtime: frequent samples read
# fresh memory values, while the original boundary audit discovers new children.
tree = ast.parse(pathlib.Path(__file__).with_name('test-real-m3-account-switch.py').read_text(encoding='utf-8'))
sampler = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'total_memory')
scans = []
children = []
class FixtureProcess:
    def __init__(self, rss): self.rss = rss
    def children(self, recursive):
        assert recursive
        scans.append(True)
        return list(children)
    def memory_info(self): return types.SimpleNamespace(rss=self.rss, private=self.rss)
owned, worker = FixtureProcess(10), FixtureProcess(20)
children.append(worker)
namespace = {'owned': owned, 'time': time, 'resource_members': None, 'resource_members_checked': None}
exec(compile(ast.Module(body=[sampler], type_ignores=[]), str(__file__), 'exec'), namespace)
assert namespace['total_memory']() == (30, 30) and len(scans) == 1
worker.rss = 40
for _ in range(50):
    assert namespace['total_memory'](refresh_members=False) == (50, 50)
assert len(scans) == 1, 'continuous sampler rescanned the OS process table'
children.append(FixtureProcess(5))
assert namespace['total_memory']() == (55, 55) and len(scans) == 2
results.append({'scenario': 'fresh RSS without extra global PID scans', 'passed': True,
                'fresh_reads': 50, 'original_audit_detects_new_descendants': True})
started = time.monotonic()
try:
    captured_run([sys.executable, '-c', 'import time; time.sleep(30)'], env=None, timeout=.2)
    raise AssertionError('command timeout was accepted')
except subprocess.TimeoutExpired:
    elapsed = time.monotonic() - started
    assert elapsed < 5, 'command cleanup exceeded deadline'
    results.append({'scenario': 'command deadline', 'passed': True, 'seconds': elapsed})

# Inject into a disposable copy, never into runtime or production source.
directory = pathlib.Path(tempfile.mkdtemp(prefix='inspector-fault-', dir=output))
source = pathlib.Path(__file__).with_name('native_fixture_process.py')
fault_source = directory / 'inspector.py'
fault_source.write_text(source.read_text(encoding='utf-8').replace(
    'import psutil\n', 'time.sleep(30)\n    import psutil\n'), encoding='utf-8')
spec = importlib.util.spec_from_file_location('fault_fixture', fault_source)
fault = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fault)
inspector = fault.WorkerInspector(directory / 'responses', timeout=.2)
started = time.monotonic()
try:
    inspector.inspect({'host_pid': 0, 'worker_pid': 0})
    raise AssertionError('unresponsive inspection was accepted')
except TimeoutError:
    elapsed = time.monotonic() - started
    assert elapsed < 5 and inspector.process.poll() is not None
    failure = json.loads((directory / 'responses/inspection-failure.json').read_text(encoding='utf-8'))
    assert failure['passed'] is False and 'deadline' in failure['error']
    results.append({'scenario': 'inspection does not respond', 'passed': True,
                    'seconds': elapsed, 'helper_reaped': True})
finally:
    inspector.close()
(output / 'fixture-process-verification.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
print(json.dumps(results), flush=True)
