from threading import Lock

class SequenceManager:

    def __init__(self):
        self._counter = 0
        self._lock = Lock()

    def next(self):
        with self._lock:
            self._counter += 1
            return self._counter