from enum import Enum
from kite.consts import REG_RA, REG_PC, SIGNAL_RETURN_ADDRESS, REG_SYSCALL_ARG0

SIGNAL_NUM = 32

SIG_DFL = 0
SIG_IGN = 1

SIG_BLOCK = 1
SIG_UNBLOCK = 2
SIG_SETMASK = 3

STATUS_EXITED = 0
def STATUS_SIGNALED(signal):
    return signal.value

def STATUS_STOPPED(signal):
    return signal.value << 8 | 0x7f

class Signal(Enum):
    SIGHUP = 1
    SIGINT = 2
    SIGQUIT = 3
    SIGILL = 4
    SIGTRAP = 5
    SIGABRT = 6
    SIGFPE = 8
    SIGKILL = 9
    SIGBUS = 10
    SIGSEGV = 11
    SIGSYS = 12
    SIGPIPE = 13
    SIGALRM = 14
    SIGTERM = 15
    SIGSTOP = 17
    SIGTSTP = 18
    SIGCONT = 19
    SIGCHLD = 20
    SIGTTIN = 21
    SIGTTOU = 22
    SIGWINCH = 28
    SIGINFO = 29
    SIGUSR1 = 30
    SIGUSR2 = 31

class DefaultAction(Enum):
    Term = 1
    Core = 2
    Ign = 3
    Stop = 4
    Cont = 5

# TODO: fill this structure
default_action = {}
default_action[Signal.SIGINT] = DefaultAction.Term
default_action[Signal.SIGTERM] = DefaultAction.Term
default_action[Signal.SIGSEGV] = DefaultAction.Term
default_action[Signal.SIGTSTP] = DefaultAction.Stop
default_action[Signal.SIGCHLD] = DefaultAction.Ign

def create_signal_context(signal, sigaction, context):
    new_context = context.copy_for_signal_handler()

    # TODO: handle sigaction["mask"] and sigaction["flags"]

    # jump to signal handler
    new_context.reg_write(REG_PC, sigaction["handler"])
    new_context.reg_write(REG_SYSCALL_ARG0, signal.value)

    # after returning from handler, jump to this address to restore previous context
    new_context.reg_write(REG_RA, SIGNAL_RETURN_ADDRESS)

    return new_context

class SignalSet:
    def __init__(self):
        self.pending_mask = [False] * (SIGNAL_NUM)
        self.blocked_mask = [False] * (SIGNAL_NUM)

    def set_pending(self, signal: Signal):
        self.pending_mask[signal.value] = True

    def unset_pending(self, signal: Signal):
        self.pending_mask[signal.value] = False

    def set_blocked(self, signal: Signal):
        self.blocked_mask[signal.value] = True

    def unset_blocked(self, signal: Signal):
        self.blocked_mask[signal.value] = False

    def is_pending(self, signal: Signal) -> bool:
        return self.pending_mask[signal.value]

    def is_blocked(self, signal: Signal) -> bool:
        return self.blocked_mask[signal.value]

    def get_any(self) -> Signal | None:
        for i in range(SIGNAL_NUM):
            if self.pending_mask[i] and not self.blocked_mask[i]:
                return Signal(i)
        return None

    def __repr__(self):
        enabled_signals = [sig.name for sig in Signal if self.is_set(sig)]
        return f"SignalMask({enabled_signals})"
