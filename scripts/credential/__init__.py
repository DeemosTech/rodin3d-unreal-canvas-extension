"""Access the Rodin Canvas session in the current user's OS credential store."""
import contextlib
import sys
import time


class StoreError(Exception):
    pass


if sys.platform == "win32":
    import msvcrt
    from . import windows as backend
elif sys.platform == "darwin":
    import fcntl
    from . import macos as backend
elif sys.platform.startswith("linux"):
    import fcntl
    from . import linux as backend
else:
    raise RuntimeError("Unsupported Rodin Canvas worker platform")


def state_dir():
    return backend.STATE_DIR


def load():
    return backend.credential("get")


def save(state):
    backend.credential("store", state)


def clear_session():
    backend.credential("erase")


@contextlib.contextmanager
def locked(tick):
    state_dir().mkdir(mode=0o700, parents=True, exist_ok=True)
    with (state_dir() / "login.lock").open("a+b") as lock:
        while True:
            lock.seek(0)
            try:
                if sys.platform == "win32":
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                tick("Waiting for the Rodin sign-in in another window")
                time.sleep(2)
        try:
            yield
        finally:
            lock.seek(0)
            if sys.platform == "win32":
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock, fcntl.LOCK_UN)
