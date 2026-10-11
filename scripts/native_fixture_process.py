"""Bound native-test process waits, including Windows handle inspection.

The inspector preserves boundary assertions in a disposable process: a hung
psutil native call must fail acceptance rather than hang its Python controller.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import traceback


def captured_run(command, *, env, timeout):
    # Regular files avoid communicate() waiting forever for inherited pipe EOF
    # after Windows subprocess.run() kills a timed-out direct child.
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        process = subprocess.Popen(command, env=env, stdout=stdout, stderr=stderr)
        try:
            process.wait(timeout=timeout)
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            raise
        stdout.seek(0)
        stderr.seek(0)
        return subprocess.CompletedProcess(command, process.returncode, stdout.read(), stderr.read())


def inspect_worker(request, phase):
    import psutil
    phase('children')
    host = psutil.Process(request['host_pid'])
    assert '--runtime-internal' in host.cmdline(), 'inspection must target the fixture runtime'
    children = [child for child in host.children(recursive=True)
                if not (sys.platform == 'win32' and child.name().lower() == 'conhost.exe')]
    assert len(children) == 1, 'expected exactly one supervised Core worker'
    worker = children[0]
    assert worker.pid == request['worker_pid'] and worker.ppid() == host.pid
    assert '--core-worker-internal' in worker.cmdline()
    assert pathlib.Path(worker.exe()).resolve() == pathlib.Path(host.exe()).resolve()
    phase('open_files')
    assert not any(pathlib.Path(file.path).name in ('rsrs.db', 'lock.db') for file in worker.open_files())
    phase('environ')
    assert not {'GH_TOKEN', 'GITHUB_TOKEN', 'OPENAI_API_KEY', 'RSRS_SUPER'} & worker.environ().keys()
    return [worker.pid, worker.create_time()]


class WorkerInspector:
    def __init__(self, directory, timeout=5):
        self.directory = pathlib.Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.timeout = timeout
        self.sequence = 0
        self.log = (self.directory / 'inspector.log').open('wb')
        self.process = subprocess.Popen([sys.executable, '-u', __file__, str(self.directory)],
                                        stdin=subprocess.PIPE, stdout=self.log, stderr=self.log)

    def inspect(self, request):
        self.sequence += 1
        request = {**request, 'sequence': self.sequence}
        response = self.directory / ('response-' + str(self.sequence) + '.json')
        self.process.stdin.write((json.dumps(request) + '\n').encode())
        self.process.stdin.flush()
        deadline = time.monotonic() + self.timeout
        while True:
            if self.process.poll() is not None:
                raise RuntimeError('worker inspector exited; see ' + str(self.directory / 'inspector.log'))
            if time.monotonic() >= deadline:
                self.close()
                raise TimeoutError('worker boundary inspection exceeded ' + str(self.timeout) +
                                   's; see ' + str(self.directory / 'inspector.log'))
            try:
                result = json.loads(response.read_text(encoding='utf-8'))
                break
            except (FileNotFoundError, PermissionError):
                # Windows may briefly deny access while a just-renamed file is
                # being closed or scanned. This shares the inspection deadline.
                time.sleep(.005)
        assert result['passed'], result.get('error')
        return tuple(result['identity'])

    def close(self):
        try:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=5)
        finally:
            self.process.stdin.close()
            self.log.close()


def serve(directory):
    import faulthandler
    faulthandler.enable()
    directory = pathlib.Path(directory)
    for line in sys.stdin:
        request = json.loads(line)
        sequence = request['sequence']
        def phase(name):
            print(json.dumps({'sequence': sequence, 'phase': name}), flush=True)
        faulthandler.dump_traceback_later(3)
        try:
            identity = inspect_worker(request, phase)
            result = {'passed': True, 'identity': identity}
        except Exception:
            result = {'passed': False, 'error': traceback.format_exc()}
        finally:
            faulthandler.cancel_dump_traceback_later()
        temporary = directory / 'response.tmp'
        temporary.write_text(json.dumps(result), encoding='utf-8')
        os.replace(temporary, directory / ('response-' + str(sequence) + '.json'))


if __name__ == '__main__':
    serve(sys.argv[1])
