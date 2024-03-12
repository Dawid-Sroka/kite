from kite.job_queue import JobQueue
from kite.process import Process


class Scheduler:
    def __init__(self):
        self.ready_queue = []

    def enqueue_process(self, process: Process):
        self.ready_queue.append(process)

    def get_process(self) -> Process | None:
        if len(self.ready_queue) == 0:
            return None
        else:
            process = self.ready_queue[0]
            return process

    def remove_process(self) -> None:
        self.ready_queue.pop(0)
