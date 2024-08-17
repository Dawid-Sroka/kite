from kite.job_queue import JobQueue
from kite.process import Process, Resource




class Scheduler:
    def __init__(self):
        self.ready_queue = []
        self.blocked_queue = []

    def enqueue_thread(self, thread):
        self.ready_queue.append(thread)

    def remove_thread(self) -> None:
        self.ready_queue.pop(0)

    # returns thread or None
    def get_thread(self):
        if len(self.ready_queue) == 0:
            return None
        else:
            first_pid, first_thread = self.ready_queue.pop(0)
            self.ready_queue.append((first_pid, first_thread))
            pid, thread = self.ready_queue[0]
            return pid, thread

    def update_processes_states(self, pid, thread, result: (str, Resource)):
        if result is None:
            return
        action, resource = result
        if action == "unblock":
            # if resource.resource_type == "process state":
            #     # wake up parent
            #     process_waited_upon = resource.resource
            for index, blocked_thread in enumerate(self.blocked_queue):
                blocked_pid, blocked_thread, blocking_resource = blocked_thread
                if blocking_resource.resource_type == resource.resource_type and \
                    resource.resource in blocking_resource.resource:
                    # blocking_resource.resource == resource.resource:
                    self.blocked_queue.pop(index)
                    self.ready_queue.append((blocked_pid, blocked_thread))
        if action == "block":
            self.ready_queue.pop(0)
            self.blocked_queue.append((pid, thread, resource))

    def dump_ready_queue(self):
        return [elem[0] for elem in self.ready_queue]

    def dump_blocked_queue(self):
        return [(elem[0], elem[2].resource) for elem in self.blocked_queue]
