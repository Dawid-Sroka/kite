from kite.job_queue import JobQueue
from kite.process import Process

from queue import Queue


class Scheduler:
    def __init__(self):
        self.job_queue = Queue()

    @classmethod
    def create(cls):
        return cls(JobQueue())

    def enqueue_process(self, process: Process):
        self.job_queue.put(process)

    def get_process(self) -> Process | None:
        if (self.job_queue.empty()):
            return None
        else:
            return self.job_queue.get()
