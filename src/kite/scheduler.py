from kite.job_queue import JobQueue
from kite.process import ProcessImage, Resource




class Scheduler:
    def __init__(self):
        self.ready_queue = []
        self.blocked_queue = []

    def enqueue_process(self, process):
        self.ready_queue.append(process)

    def remove_process(self) -> None:
        self.ready_queue.pop(0)

    # returns process or None
    def get_process_entry(self):
        if len(self.ready_queue) == 0:
            return None
        else:
            first_pid, first_process = self.ready_queue.pop(0)
            self.ready_queue.append((first_pid, first_process))
            pid, process = self.ready_queue[0]
            return pid, process

    def update_processes_states(self, pid, process, result: (str, Resource)):
        if result is None:
            return
        action, resource = result
        if action == "unblock":
            # if resource.resource_type == "process state":
            #     # wake up parent
            #     process_waited_upon = resource.resource
            for index, blocked_process in enumerate(self.blocked_queue):
                blocked_pid, blocked_process, blocking_resource = blocked_process
                if blocking_resource.resource_type == resource.resource_type and \
                    resource.resource in blocking_resource.resource:
                    # blocking_resource.resource == resource.resource:
                    self.blocked_queue.pop(index)
                    self.ready_queue.append((blocked_pid, blocked_process))
        if action == "block":
            self.ready_queue.pop(0)
            self.blocked_queue.append((pid, process, resource))

    def dump_ready_queue(self):
        return [elem[0] for elem in self.ready_queue]

    def dump_blocked_queue(self):
        return [(elem[0], elem[2].resource) for elem in self.blocked_queue]
