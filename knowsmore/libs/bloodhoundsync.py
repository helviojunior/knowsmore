from typing import Any
import queue
import threading


class BloodhoundSync:
    __running = False
    q = None
    __total = 0
    __count = 0
    threads = 1
    callback = None
    per_thread_callback = None
    inserted = []

    def __init__(self, callback: Any = None, per_thread_callback: Any = None, threads=2):
        if callback is None or not callable(callback):
            raise Exception('worker is not callable')

        if per_thread_callback is not None and not callable(per_thread_callback):
            raise Exception('per_thread_callback is not callable')

        self.callback = callback
        self.per_thread_callback = per_thread_callback
        self.q = queue.Queue()
        self.threads = threads
        self.total = 0
        self.inserted = []
        if self.threads <= 1:
            self.threads = 1

    def __enter__(self):
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.close()

    def add_item(self, id, item) -> bool:
        if id not in self.inserted:
            self.inserted.append(id)
            self.q.put(item)
            self.__total += 1
            return True
        return False

    def start(self, **kwargs):

        if self.callback is None or not callable(self.callback):
            raise Exception('The worker is not callable')

        self.__running = True
        self.__count = 0
        for i in range(self.threads):
            t = threading.Thread(target=self.__worker, kwargs=dict(index=i, **kwargs))
            t.daemon = True
            t.start()

    def __worker(self, index, **kwargs):
        tcb = None
        if self.per_thread_callback is not None:
            tcb = self.per_thread_callback(index, **kwargs)

        while self.__running:
            entry = self.q.get()

            if entry is None:
                self.q.task_done()
                continue

            try:
                self.callback(entry=entry, thread_callback_data=tcb, **kwargs)
            finally:
                self.__count += 1
                self.q.task_done()

    @property
    def count(self):
        return len(self.q.queue)

    @property
    def executed(self):
        return self.__count

    @property
    def running(self):
        return self.__running

    def close(self):
        self.__running = False
        self.inserted = []
        with self.q.mutex:
            self.q.queue.clear()
