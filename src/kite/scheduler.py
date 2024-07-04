from kite.job_queue import JobQueue
from kite.process import Process


class Scheduler:
    def __init__(self):
        self.ready_queue = []
        self.blocked_queue = []

    def enqueue_thread(self, thread):
        self.ready_queue.append(thread)

    # returns thread or None
    def get_thread(self):
        if len(self.ready_queue) == 0:
            return None
        else:
            first_thread = self.ready_queue.pop(0)
            self.ready_queue.append(first_thread)
            thread = self.ready_queue[0]
            return thread

    def move_to_blocked(self, thread):
        blocked_thread = self.ready_queue.pop(0)
        self.blocked_queue.append(blocked_thread)

    def move_to_ready(self, thread):
        ready_thread = self.blocked_queue.pop(0)
        self.ready_queue.append(ready_thread)

    def remove_thread(self) -> None:
        self.ready_queue.pop(0)
