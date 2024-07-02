from kite.job_queue import JobQueue
from kite.process import Process


class Scheduler:
    def __init__(self):
        self.ready_queue = []

    def enqueue_thread(self, thread):
        self.ready_queue.append(thread)

    # returns thread or None
    def get_thread(self):
        if len(self.ready_queue) == 0:
            return None
        else:
            thread = self.ready_queue[0]
            return thread

    def remove_thread(self) -> None:
        self.ready_queue.pop(0)
