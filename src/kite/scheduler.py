from kite.job_queue import JobQueue
from kite.process import ProcessImage, Resource
from collections import deque
from kite.signals import Signal




class Scheduler:
    def __init__(self):
        self.ready_queue = []
        self.blocked_queue = []
        self.unreported_stopped_processes = deque()
        self.reported_stopped_processes = deque()

    @property
    def stopped_processes(self):
        res = deque(self.unreported_stopped_processes)
        res.extend(self.reported_stopped_processes)
        return res

    def enqueue_process(self, process):
        self.ready_queue.append(process)

    def remove_process(self) -> None:
        self.ready_queue.pop(0)

    def stop_process(self):
        process = self.ready_queue.pop(0)
        self.unreported_stopped_processes.append(process)

    # returns process or None
    def get_process_entry(self):
        if len(self.ready_queue) == 0:
            return None
        else:
            first_process = self.ready_queue.pop(0)
            self.ready_queue.append(first_process)
            process = self.ready_queue[0]
            return process

    def reasume_continued_processes(self):
        for process in self.reported_stopped_processes.copy() + self.unreported_stopped_processes.copy():
            if process.signal_set.is_pending(Signal.SIGCONT):
                process.signal_set.unset_pending(Signal.SIGCONT)
                self.reported_stopped_processes.remove(process)
                self.enqueue_process(process)

    def update_processes_states(self, process, result: (str, Resource)):
        for index, (blocked_process, blocked_resource) in enumerate(self.blocked_queue):
            if blocked_resource.resource_type == "signal" and blocked_process.signal_set.get_any():
                self.blocked_queue.pop(index)
                self.ready_queue.append(blocked_process)

        if result is None:
            return
        action, resource = result
        if action == "unblock" or resource.resource_type == "stdin":
            # if resource.resource_type == "process state":
            #     # wake up parent
            #     process_waited_upon = resource.resource
            for index, blocked_process in enumerate(self.blocked_queue):
                blocked_process, blocking_resource = blocked_process
                if blocking_resource.resource_type == resource.resource_type and \
                    resource.resource in blocking_resource.resource:
                    # blocking_resource.resource == resource.resource:
                    self.blocked_queue.pop(index)
                    self.ready_queue.append(blocked_process)
        elif action == "block":
            self.ready_queue.pop(0)
            self.blocked_queue.append((process, resource))

    def dump_ready_queue(self):
        return [elem.pid for elem in self.ready_queue]

    def dump_blocked_queue(self):
        return [(elem[0].pid, elem[1].resource) for elem in self.blocked_queue]
