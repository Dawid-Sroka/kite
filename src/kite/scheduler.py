from kite.job_queue import JobQueue
from kite.process import Process


class Resource:
    def __init__(self, resource_type, resource):
        self.resource_type = resource_type
        self.resource = resource

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
                    blocking_resource.resource == resource.resource:
                    self.blocked_queue.pop(index)
                    self.ready_queue.append((blocked_pid, blocked_thread))
        if action == "block":
            self.ready_queue.pop(0)
            self.blocked_queue.append((pid, thread, resource))
