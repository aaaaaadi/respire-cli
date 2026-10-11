"""Verify fixture deadlines fail explicitly and reap their owned inspector."""
import argparse
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import time

from native_fixture_process import captured_run

parser = argparse.ArgumentParser()
parser.add_argument('--output-dir', required=True)
args = parser.parse_args()
output = pathlib.Path(args.output_dir).resolve()
output.mkdir(parents=True, exist_ok=False)
results = []
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
