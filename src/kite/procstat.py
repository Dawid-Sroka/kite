from kite.process import VirtualFile

def generate_procstat_data(kernel_state):
    proc_data = []
    zombies = []
    for process in kernel_state.scheduler.ready_queue:
        proc_data.append((process.pid, process.ppid, process.pgid, 'R', process.command))
        zombies += process.zombies
    for process, _ in kernel_state.scheduler.blocked_queue:
        proc_data.append((process.pid, process.ppid, process.pgid, 'S', process.command))
        zombies += process.zombies
    for process in kernel_state.scheduler.stopped_processes:
        proc_data.append((process.pid, process.ppid, process.pgid, 'T', process.command))
        zombies += process.zombies
    for process in zombies:
        proc_data.append((process.pid, process.ppid, process.pgid, 'Z', process.command))

    # sort by PIDs
    proc_data.sort(key=lambda x: x[1])
    res = ""
    for pid, ppid, pgrp, state, command in proc_data:
        res += f'0\t{pid}\t{ppid}\t{pgrp}\t0\t{state}\t{command}\n'
    return res

procstat_creator = lambda kernel_state: VirtualFile("/dev/procstat", generate_procstat_data(kernel_state))
