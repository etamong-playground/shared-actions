from contextlib import contextmanager
from contextvars import ContextVar
import os
import selectors
import signal
import subprocess
import time

DEADLINE = ContextVar('source_scan_deadline', default=None)


@contextmanager
def budget(seconds):
    token = DEADLINE.set(time.monotonic() + seconds)
    try:
        yield
    finally:
        DEADLINE.reset(token)


class IncompleteScan(Exception):
    pass


@contextmanager
def interruption():
    def stop(_number, _frame):
        raise IncompleteScan()
    previous = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        for number in previous:
            signal.signal(number, stop)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def run(command, *, cwd, env, timeout=180, output_bytes=2 * 1024 * 1024):
    if timeout <= 0 or output_bytes <= 0:
        raise IncompleteScan()
    deadline = time.monotonic() + timeout
    if DEADLINE.get() is not None:
        deadline = min(deadline, DEADLINE.get())
    if deadline <= time.monotonic():
        raise IncompleteScan()
    blocked = {signal.SIGINT, signal.SIGTERM}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    try:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
    except BaseException:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        raise
    output = [bytearray(), bytearray()]
    total = 0
    try:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((process.stdout, process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise IncompleteScan()
                for key, _ in selector.select(min(remaining, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), min(65536, output_bytes - total + 1))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    total += len(chunk)
                    if total > output_bytes:
                        raise IncompleteScan()
                    output[key.data].extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise IncompleteScan()
            code = process.wait(timeout=remaining)
            return code, bytes(output[0]), bytes(output[1])
    except (OSError, subprocess.SubprocessError):
        raise IncompleteScan() from None
    finally:
        cleanup_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
        try:
            cleanup_failed = False
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                cleanup_failed = True
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                process.wait(timeout=5)
            except subprocess.SubprocessError:
                cleanup_failed = True
            finally:
                process.stdout.close()
                process.stderr.close()
            if cleanup_failed:
                raise IncompleteScan()
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, cleanup_mask)
