import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('scanner_process', ROOT / '.github/actions/source-secret-scan/process.py')
PROCESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROCESS)


class ScannerProcessTests(unittest.TestCase):
    def execute(self, source, **kwargs):
        return PROCESS.run([sys.executable, '-c', source], cwd=ROOT, env={}, **kwargs)

    def test_captures_both_streams_and_exit_without_forwarding_them(self):
        code, output, error = self.execute('import sys; print("fixture output"); print("fixture error",file=sys.stderr); sys.exit(7)')
        self.assertEqual(code, 7)
        self.assertEqual(output, b'fixture output\n')
        self.assertEqual(error, b'fixture error\n')

    def test_cleanup_permission_failure_is_incomplete_and_reaps_leader(self):
        original = subprocess.Popen
        children = []
        def start(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        with patch.object(PROCESS.subprocess, 'Popen', side_effect=start), \
             patch.object(PROCESS.os, 'killpg', side_effect=PermissionError):
            with self.assertRaises(PROCESS.IncompleteScan):
                self.execute('print("controlled output")')
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        self.assertTrue(children[0].stdout.closed)
        self.assertTrue(children[0].stderr.closed)

    def test_combined_output_budget_applies_to_both_streams(self):
        with self.assertRaises(PROCESS.IncompleteScan):
            self.execute('import os; os.write(1,b"a"*8); os.write(2,b"b"*8)', output_bytes=10)

    def test_exact_output_budget_is_accepted(self):
        code, output, error = self.execute('import os; os.write(1,b"a"*10)', output_bytes=10)
        self.assertEqual((code, output, error), (0, b'a' * 10, b''))

    def test_continuous_output_is_stopped_before_unbounded_capture(self):
        with self.assertRaises(PROCESS.IncompleteScan):
            self.execute('import os\nwhile True: os.write(1,b"x"*65536)', output_bytes=1024)

    def test_deadline_applies_when_pipes_close_before_process_exit(self):
        started = time.monotonic()
        with self.assertRaises(PROCESS.IncompleteScan):
            self.execute('import os,time; os.close(1); os.close(2); time.sleep(10)', timeout=0.2)
        self.assertLess(time.monotonic() - started, 3)

    def test_descendant_holding_output_cannot_outlive_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / 'child'
            source = ('import os,time\n'
                      'pid=os.fork()\n'
                      f'if pid: open({str(pid_path)!r},"w").write(str(pid)); os._exit(0)\n'
                      'time.sleep(10)')
            with self.assertRaises(PROCESS.IncompleteScan):
                self.execute(source, timeout=0.3)
            self.assertTrue(pid_path.exists())
            pid = int(pid_path.read_text())
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            # A killed child may remain a zombie until the host reaps it.
            import subprocess
            state = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()
            self.assertTrue(not state or state.startswith('Z'), state)

    def test_child_receives_only_the_supplied_environment(self):
        code, output, error = self.execute('import os; print(os.getenv("GH_TOKEN", "absent"))')
        self.assertEqual((code, output, error), (0, b'absent\n', b''))

    def test_invalid_limits_fail_before_execution(self):
        for limits in [{'timeout': 0}, {'output_bytes': 0}]:
            with self.subTest(limits=limits), self.assertRaises(PROCESS.IncompleteScan):
                self.execute('raise AssertionError("must not run")', **limits)

    def test_aggregate_budget_is_shared_across_processes(self):
        with patch.object(PROCESS.time, 'monotonic', return_value=100) as clock:
            with PROCESS.budget(60):
                self.execute('pass')
                clock.return_value = 161
                with patch.object(PROCESS.subprocess, 'Popen', side_effect=AssertionError('expired budget spawned child')):
                    with self.assertRaises(PROCESS.IncompleteScan):
                        self.execute('pass')

    def test_cancellation_removes_scratch_and_kills_descendant_with_fixed_output(self):
        helpers = ROOT / '.github/actions/source-secret-scan'
        for number in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=number), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                marker = root / 'child'
                child = 'import os,time;open(' + repr(str(marker)) + ',"w").write(str(os.getpid()));time.sleep(30)'
                wrapper = ('import sys,tempfile\nfrom pathlib import Path\n'
                           'sys.path.insert(0,' + repr(str(helpers)) + ')\n'
                           'from process import run,interruption,IncompleteScan\n'
                           'try:\n'
                           ' with interruption(), tempfile.TemporaryDirectory(dir=' + repr(directory) + ') as scratch:\n'
                           '  run([sys.executable,"-c",' + repr(child) + '],cwd=Path(scratch),env={},timeout=30)\n'
                           'except IncompleteScan:\n print("Source scan incomplete.");sys.exit(2)\n')
                process = subprocess.Popen([sys.executable, '-c', wrapper], stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 5
                    while not marker.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(marker.exists(), 'Fixture did not start')
                    process.send_signal(number)
                    output, error = process.communicate(timeout=5)
                    self.assertEqual((process.returncode, output, error), (2, 'Source scan incomplete.\n', ''))
                    self.assertEqual(list(root.iterdir()), [marker])
                    pid = marker.read_text()
                    state = subprocess.run(['ps', '-o', 'stat=', '-p', pid], capture_output=True, text=True).stdout.strip()
                    self.assertTrue(not state or state.startswith('Z'), state)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate()


if __name__ == '__main__':
    unittest.main()
