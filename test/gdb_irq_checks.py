"""GDB-side checks for interrupt/exception handlers (targets whose test
firmware has exception vectors: see test/firmware/<isa>/irq.S, irq.c and
test/ghidra_setup_irq.py). Run inside gdb-multiarch via -x.

The handlers save the interrupted context (incl. the interrupt return
register, e.g. SRR0) in an exception frame and call C functions. The
exported CFI must unwind from those C functions, through the handler, into
the exact interrupted instruction.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gdb_helpers import *  # noqa: E402,F401,F403


def frames():
    out = []
    f = gdb.newest_frame()
    while f is not None:
        out.append(f)
        f = f.older()
    return out


def func_at(pc):
    """Function name containing pc (also for signal-handler frames)."""
    b = gdb.current_progspace().block_for_pc(pc)
    while b is not None and b.function is None:
        b = b.superblock
    return b.function.name if b is not None else None


def check_irq_backtrace(label, handler_fn, handler_frame_fn, interrupted):
    """frame 0 = C handler, frame 1 = the assembly handler (a signal frame),
    frame 2 = the interrupted function, ..., ending at _reset."""
    fs = frames()
    names = [f.name() for f in fs]
    check("%s: frame 0" % label, names and names[0] == handler_fn, names)
    if len(fs) < 3:
        check("%s: unwinds through the handler" % label, False, names)
        return fs
    if os.environ.get("IRQ_SIGNAL_FRAME", "1") == "1":
        check("%s: handler frame is an interrupt (signal) frame" % label,
              fs[1].type() == gdb.SIGTRAMP_FRAME, str(fs[1].type()))
    check("%s: handler frame is in %s" % (label, handler_frame_fn),
          func_at(fs[1].pc()) == handler_frame_fn, func_at(fs[1].pc()))
    check("%s: interrupted function" % label, names[2] in interrupted, names)
    check("%s: backtrace reaches _reset" % label, names[-1] == "_reset", names)
    out = run("bt")
    check("%s: backtrace ends cleanly" % label, "Backtrace stopped" not in out, out)
    return fs


def main():
    setup_session()

    # --- system call: complete handler at the 0xc00 vector -------------------
    cont_to("syscall_handler")
    check_eq("syscall arg num", "num", 7)
    check_eq("syscall arg arg", "arg", 35)
    fs = check_irq_backtrace("sc", "syscall_handler", "sc_vector", ("do_syscall",))
    if len(fs) > 3:
        fs[2].select()
        # do_syscall's r3/r4 come back from the exception frame
        check_eq("interrupted frame arg (saved r3)", "num", 7)
        check_eq("interrupted frame arg (saved r4)", "arg", 35)
        check("interrupted PC is exact (instruction after sc)",
              fs[2].pc() == int(val("(unsigned long)&do_syscall")) + 4, hex(fs[2].pc()))
        check("interrupted frame unwinds to its caller", fs[3].name() == "irq_test", fs[3].name())
        fs[0].select()
    check_finish("finish from C handler returns", 42)
    check("finish stops in the handler", func_at(gdb.selected_frame().pc()) == "sc_vector",
          func_at(gdb.selected_frame().pc()))

    # --- program check: "b prog_entry" stub tagged INTERRUPT ------------------
    cont_to("program_check")
    check_eq("faulting pc argument", "pc == (unsigned long)&trap_now", 1)
    check_irq_backtrace("program check", "program_check", "prog_entry", ("trap_now",))

    # --- decrementer: nops + b dec_entry at the 0x900 vector ------------------
    cont_to("timer_tick")
    fs = check_irq_backtrace("decrementer", "timer_tick", "dec_entry", ("busy_work", "irq_test"))
    if len(fs) > 2:
        interrupted_pc = fs[2].pc()
        check("interrupted frame has line info",
              fs[2].find_sal().symtab is not None, str(fs[2].find_sal()))

    # Before the handler stores SRR0 the interrupted context is only in SPRs,
    # which DWARF can't name for GDB: the backtrace must stop cleanly there.
    cont_to("*(unsigned long)&dec_vector")
    fs = frames()
    check("vector stub: frame 0", func_at(fs[0].pc()) == "dec_vector", func_at(fs[0].pc()))
    out = run("bt")
    check("vector stub: backtrace stops without error", "Error" not in out and len(fs) >= 1, out)

    # After SRR0 is stored, the full chain is back (dec_entry: stwu, stw r0,
    # mfsrr0, stw -> the 5th instruction onwards).
    cont_to("*((unsigned long)&dec_entry + 16)")
    fs = frames()
    names = [func_at(f.pc()) for f in fs]
    check("handler after SRR0 save unwinds to interrupted code",
          len(names) > 1 and names[1] in ("busy_work", "irq_test"), names)

    # Step over rfi back into the interrupted code.
    rfi_pc = None
    for line in run("x/80i (unsigned long)&dec_entry").splitlines():
        m = re.search(r"(0x[0-9a-f]+) <dec_entry\+\d+>:\s+rfi", line)
        if m:
            rfi_pc = int(m.group(1), 16)
            break
    check("found the rfi", rfi_pc is not None)
    if rfi_pc is not None:
        cont_to("*0x%x" % rfi_pc)
        run("stepi")
        here = func_at(gdb.selected_frame().pc())
        check("stepi over rfi returns to the interrupted function", here in ("busy_work", "irq_test"), here)

    # --- end state ----------------------------------------------------------------
    cont_to("edge_main")
    check_eq("syscall result", "g_irq_result[0]", 42)
    check_eq("traps", "g_irq_result[1]", 1)
    check_eq("trap pc", "g_trap_pc == (unsigned long)&trap_now", 1)
    check_eq("irq_test finished", "g_irq_result[3]", 0x1234)
    check("ticks", int(val("g_ticks")) >= 3, str(val("g_ticks")))


run_checks(main)
