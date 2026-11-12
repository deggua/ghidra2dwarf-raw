"""GDB features beyond breakpoints/backtraces that depend on the exported
debug info: inferior function calls, 'return', watchpoints (incl. a local
whose scope ends when its frame is popped), 'advance', 'until', 'jump' and
'info frame'. Run inside gdb-multiarch via -x, in its own QEMU session: the
checks change the program's behaviour (forced return value, skipped code).

Env: ELF, CSRC, QEMU_PORT, BUILD (firmware build dir with layout.json).
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gdb_helpers import *  # noqa: E402,F401,F403

with open(os.path.join(os.environ["BUILD"], "layout.json")) as _f:
    LAYOUT = json.load(_f)

# GDB's inferior calls follow the architecture's standard ABI; it does not
# use DWARF parameter locations. Programs compiled with a non-standard
# convention (i386 -mregparm) can't be called correctly (see README).
CALL_OK = LAYOUT.get("calling_convention") not in ("__regparm3",)

# forced return value of clamp() in the 'return' check
FORCED = 77


def cont_raw():
    """'continue' without the cont_to() bookkeeping; returns GDB's output."""
    return run("continue")


def delete_all():
    for b in gdb.breakpoints() or []:
        b.delete()


def pc_of_line(line):
    sals = gdb.decode_line(spec(line))[1]
    return min(int(s.pc) for s in sals) if sals else None


def main():
    setup_session()

    # --- "break func" shows the function's first statement -------------------
    # (not a later one: no flag-setting compare taken for prologue, and the
    # earliest statement among instructions scheduled before the first branch)
    late = []
    for fn in ("clamp", "fact", "filter_offset", "mul64", "many_args", "process_all", "sensor_update",
               "update_stats", "shape_leaf", "shape_csel", "shape_build", "shape_alias", "shape_poke"):
        try:
            b = gdb.Breakpoint(fn, internal=True)
            pc = int(b.locations[0].address)
            b.delete()
        except (gdb.error, IndexError, RuntimeError):
            continue
        blk = gdb.current_progspace().block_for_pc(pc)
        while blk is not None and blk.function is None:
            blk = blk.superblock
        sal = gdb.find_pc_line(pc)
        if blk is None or sal.symtab is None:
            continue
        lines = sorted(set(e.line for e in sal.symtab.linetable() if blk.start <= e.pc < blk.end and e.line))
        if len(lines) >= 2 and sal.line > lines[1]:
            late.append("%s: line %d, first statement %d" % (fn, sal.line, lines[1]))
    check("break func shows the first statement", not late, late)

    # --- first clamp(): v=514 via filter_double ----------------------------
    cont_to("clamp")
    check_eq("clamp v", "v", 514)
    try:
        out = run("info frame")
        check("info frame: caller frame", "called by frame at" in out, out)
        select_frame("sensor_update")
        out = run("info frame")
        check("info frame (non-leaf caller): saved registers listed", "Saved registers:" in out, out)
    except gdb.error as e:
        if "Could not fetch register" not in str(e):
            raise
        # qemu-mipsn32's stub rejects some register reads; GCC's own debug
        # info fails the same way
        print("SKIP info frame (%s)" % e)
    run("frame 0")
    before = frame_names()

    # --- inferior function calls ----------------------------------------------
    if CALL_OK:
        check_eq("call fact(4)", "fact(4)", 24)
        check_eq("call filter_offset(5)", "filter_offset(5)", 105)
        check_eq("call clamp(5000,-1,1)", "clamp(5000, -1, 1)", 1)
        if LAYOUT["lang"].startswith("AARCH64:BE"):
            # GDB misplaces 4-byte stack arguments of big-endian AArch64
            # inferior calls (same result with GCC's own debug info)
            print("SKIP call many_args (GDB bug: aarch64_be stack arguments)")
        else:
            check_eq("call many_args (stack args)", "many_args(1,2,3,4,5,6,7,8,9,10)", 385)
        check_eq("call mul64 (int64 args/return)", "mul64(0x100000000LL, 3)", 0x300000001)
        check_eq("call through function pointer", "g_sensors[1].filter(1)", 101)
        check_eq("call with a struct pointer", "sum_history(&g_sensors[2])", 0)
        check("frames unchanged after calls", frame_names() == before, frame_names())
        check_eq("clamp v after calls", "v", 514)
    else:
        print("SKIP inferior calls (non-standard calling convention: GDB calls by the default ABI)")

    # --- return: force clamp() to return 77 ------------------------------------
    try:
        run("return %d" % FORCED)
        here = gdb.selected_frame().name()
        # filter_double may tail-call clamp (-O2): then we land in sensor_update
        check("return pops to the caller", here in ("filter_double", "sensor_update"), here)
        check("return: rest of the stack intact", frame_names() == before[1:], frame_names())
    except gdb.error as e:
        check("return", False, str(e))
    cont_to("update_stats")
    check_eq("forced return value reached update_stats", "v", FORCED)
    check_eq("caller state survived the return (st)", "st", int(val("&g_stats")))

    # --- watchpoint on a global -------------------------------------------------
    # (the stop is reported asynchronously, not in 'continue' output: check
    # through the breakpoint objects and the program state)
    delete_all()
    wp = gdb.Breakpoint("g_counter", gdb.BP_WATCHPOINT)
    try:
        cont_raw()
    except gdb.error:
        # no hardware watchpoints in this stub (QEMU user mode): "Command aborted."
        delete_all()
        run("set can-use-hw-watchpoints 0")
        wp = gdb.Breakpoint("g_counter", gdb.BP_WATCHPOINT)
        cont_raw()
    check("watch g_counter fires", wp.hit_count == 1, wp.hit_count)
    check_eq("watch g_counter new value", "g_counter", 6)
    check("watchpoint stops in fw_main", gdb.selected_frame().name() == "fw_main",
          gdb.selected_frame().name())
    delete_all()

    # --- advance to a function -------------------------------------------------
    run("advance process_all")
    check("advance process_all", gdb.selected_frame().name() == "process_all",
          gdb.selected_frame().name())
    check_eq("advance: round argument", "round", 1)

    # --- watchpoint on a local: GDB stops when its frame is popped -------------
    m = re.search(r"\b(\w+) = \1 \+ 1;", func_text("process_all"))
    counter = m.group(1) if m else None
    try:
        if counter is None:
            raise gdb.error("no counter variable in the decompiled process_all")
        where = run("info address %s" % counter)
        if "register" in where or "multi" in where or "optimized out" in where:
            # GDB's software watchpoints on register-located variables are
            # unreliable; only watch a stack-resident local
            raise gdb.error("%s is not in memory: %s" % (counter, where.strip()))
        wp = gdb.Breakpoint(counter, gdb.BP_WATCHPOINT)
    except gdb.error as e:
        wp = None
        print("SKIP local watchpoint (%s)" % e)
    if wp is not None:
        hits = 0
        for _ in range(12):
            cont_raw()
            if not wp.is_valid():
                break
            hits = wp.hit_count
        check("local watchpoint sees %s change" % counter, hits >= 1, hits)
        check("local watchpoint deleted when process_all returns", not wp.is_valid(),
              gdb.selected_frame().name())
        check("stopped in the caller after scope exit", gdb.selected_frame().name() == "fw_main",
              gdb.selected_frame().name())
        delete_all()

    if gdb.selected_frame().name() == "process_all":
        check_finish("finish process_all (round 1)", 2)

    # --- until a later line ------------------------------------------------------
    fw_line = line_of(r"^void (?:__\w+ )?fw_main\(void\)")
    sum_line = line_of(r"sum_history\(", fw_line)
    run("until %s" % spec(sum_line))
    f = gdb.selected_frame()
    check("until reaches the line", f.name() == "fw_main" and f.find_sal().line == sum_line,
          "%s:%s" % (f.name(), f.find_sal().line))
    check_eq("process_all ran 3 times before it", "g_result[4]", 2)

    # --- jump over the sum_history() call ------------------------------------------
    # Target: the instruction after the call (line boundaries in optimized
    # code aren't safe resume points: the idle loop's line may start past its
    # address setup).
    loop_line = BACKSTOP_LINE[0]
    pc_loop = pc_of_line(loop_line)
    here = int(gdb.selected_frame().pc())
    dis = run("x/%di $pc" % max(1, (pc_loop - here) // 2)) if pc_loop and pc_loop > here else ""
    addrs = []
    for l in dis.splitlines():
        m = re.search(r"(0x[0-9a-f]+)", l)
        if m:
            addrs.append((int(m.group(1), 16), l))
    target = None
    for i, (a, l) in enumerate(addrs[:-1]):
        if "sum_history" in l and a < pc_loop:
            target = addrs[i + 1][0]
            break
    if target is None:
        print("SKIP jump (no call to sum_history before the idle loop)")
    else:
        run("tbreak %s" % spec(loop_line))
        run("jump *0x%x" % target)
        f = gdb.selected_frame()
        check("jump continues to the idle loop", f.name() == "fw_main" and f.find_sal().line >= loop_line,
              "%s:%s" % (f.name(), f.find_sal().line))
        check_eq("code after the jump target ran", "g_result[7]", 0x600d)
        # with clamp() forced to return 77 the real sum would be 77+534+554
        check("skipped call did not run", int(val("g_result[5]")) != 77 + 534 + 554, str(val("g_result[5]")))
        run("stepi 20")
        check("still in the idle loop", gdb.selected_frame().name() == "fw_main",
              gdb.selected_frame().name())


run_checks(main)
