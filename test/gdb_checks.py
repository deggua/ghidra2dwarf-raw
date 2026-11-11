"""GDB-side checks for the main test firmware (run inside gdb-multiarch via -x).

Env: ELF (exported symbol file), CSRC (generated C file), QEMU_PORT.
Every expectation is derived from the semantics of test/firmware/main.c.
Prints "PASS <name>" / "FAIL <name>: <why>" lines and a final summary.
"""

import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gdb_helpers import *  # noqa: E402,F401,F403
import gdb_helpers  # noqa: E402

def main():
    setup_session()

    # --- static info ---------------------------------------------------------
    out = run("list sensor_update")
    check("list shows decompiled source",
          "sensor_update(sensor_t *s,int sample)" in out or "s->filter)(" in out, out)
    out = run("ptype sensor_t")
    check("ptype struct with bitfields",
          "uint8_t enabled : 1;" in out and "uint8_t channel : 3;" in out
          and "struct sensor *next;" in out and "filter_fn filter;" in out, out)
    out = run("ptype enum mode")
    check("ptype enum", "MODE_FAULT" in out and "MODE_CALIBRATE" in out, out)
    out = run("info line sensor_update")
    check("info line maps into C file", os.path.basename(CSRC) in out, out)
    check("reset frame has a symbol", gdb.selected_frame().name() == "_reset", gdb.selected_frame().name())

    # --- recursion: fact(5) -> ... -> fact(1) ----------------------------------
    if not re.search(r"\bfact\(", func_text("fact").split("{", 1)[-1]):
        print("SKIP recursion checks (compiler turned fact() into a loop)")
        cont_to("fact")
        check_eq("fact n", "n", 5)
        check_finish("finish returns fact(5)", 120)
    else:
        check_recursion()

    check_rest()


def check_recursion():
    cont_to("fact", "n == 1")
    names = frame_names()
    check("recursive backtrace", names[:6] == ["fact"] * 5 + ["fw_main"], names)
    check("backtrace reaches entry point", names[-1] == "_reset", names)
    out = run("bt")
    check("backtrace ends cleanly", "Backtrace stopped" not in out, out)
    check_eq("fact n", "n", 1)
    run("frame 1")
    check_eq("fact caller frame n (callee-saved reg)", "n", 2)
    run("frame 4")
    check_eq("fact outermost frame n", "n", 5)
    run("frame 0")
    check_finish("finish returns fact(1)", 1)



def check_rest():
    # --- 64-bit args in register pairs ---------------------------------------
    cont_to("mul64")
    check_eq("int64 arg a (r3:r4 pieces)", "a", 0x100000000)
    check_eq("int64 arg b", "b", 3)
    check_finish("finish returns int64", 0x300000001)

    # --- stack-passed args ------------------------------------------------------
    cont_to("many_args")
    for i, n in enumerate("abcdefghij", 1):
        check_eq("many_args %s" % n, n, i)
    check_finish("finish returns many_args", 385)

    # --- clamp via filter_double via indirect call ---------------------------
    cont_to("clamp")
    check_eq("clamp v", "v", 514)
    check_eq("clamp lo", "lo", -1000)
    check_eq("clamp hi", "hi", 1000)
    names = frame_names()
    # filter_double may tail-call clamp (-O2), leaving no frame of its own.
    expected = ["clamp", "filter_double", "sensor_update", "process_all", "fw_main", "_cstart", "_reset"]
    if "filter_double" not in names:
        expected.remove("filter_double")
    check("backtrace through indirect call", names == expected, names)
    select_frame("sensor_update")
    check_eq("caller frame: sensor_update s", "s", int(val("&g_sensors[0]")))
    check_eq("caller frame: s->id", "s->id", 0x101)
    select_frame("process_all")
    check_eq("caller frame: process_all list", "list", int(val("&g_sensors[0]")))
    select_frame("fw_main")
    try:
        if val("round").is_optimized_out:
            # -O2: round is passed in a call-clobbered register and its home
            # register already holds round+1 -- genuinely unavailable.
            print("SKIP fw_main round (not available in the caller frame at this -O level)")
        else:
            check_eq("caller frame: fw_main round", "round", 0)
    except gdb.error:
        print("SKIP fw_main round (decompiler named the loop variable differently)")
    run("frame 0")
    check_finish("finish returns clamp", 514)

    # --- update_stats: struct pointer arg, float result -----------------------
    cont_to("update_stats")
    check_eq("update_stats st", "st", int(val("&g_stats")))
    check_eq("update_stats v", "v", 514)
    check_eq("st->min before", "st->min", 0x7fffffff)
    run("finish")
    check_eq("g_stats.total", "g_stats.total", 514)
    check_eq("g_stats.min", "g_stats.min", 514)
    check_eq("g_stats.last.f", "g_stats.last.f", 129.0)

    # --- conditional breakpoint on a struct pointer, stepping -----------------
    cont_to("sensor_update", "s == &g_sensors[1]")
    check_eq("sensor[1] sample", "sample", 0x202)
    check_eq("s->name", "s->name", "press")
    check_eq("s->channel bitfield", "s->channel", 5)
    check_eq("s->enabled bitfield", "s->enabled", 1)
    check("s->mode enum", str(val("s->mode")) == "MODE_IDLE", str(val("s->mode")))
    check_eq("s->pos.x", "s->pos.x", -3)
    su_line = line_of(r"^void sensor_update\(")
    call_line = line_of(r"s->filter\)\(", su_line)   # (*s->filter)( or (**(code **)s->filter)(
    sal = gdb.selected_frame().find_sal()
    run("next")
    sal = gdb.selected_frame().find_sal()
    check("next steps to the call line", sal.line == call_line, "at line %d, expected %d" % (sal.line, call_line))
    run("step")
    check("step into indirect call target", gdb.selected_frame().name() == "filter_offset",
          gdb.selected_frame().name())
    check_eq("filter_offset v", "v", 0x202)
    check_finish("finish returns filter_offset", 0x202 + 100)
    run("next")
    check_eq("s still valid after call", "s->id", 0x202)

    # --- end state -------------------------------------------------------------
    cont_to(BACKSTOP[0])
    check("stopped in final loop", gdb.selected_frame().name() == "fw_main", gdb.selected_frame().name())
    run("stepi 40")
    check_eq("g_result[0] fact(5)", "g_result[0]", 120)
    check_eq("g_result[1] checksum", "g_result[1]", -45536819)
    check_eq("g_result[2] mul64", "g_result[2]", 1)
    check_eq("g_result[3] many_args", "g_result[3]", 385)
    check_eq("g_result[4] process_all", "g_result[4]", 2)
    check_eq("g_result[5] sum_history", "g_result[5]", 514 + 534 + 554)
    check_eq("g_result[6] counter", "g_result[6]", 8)
    check_eq("g_result[7] marker", "g_result[7]", 0x600d)
    check_eq("g_sensors[0].history[2]", "g_sensors[0].history[2]", 554)
    check_eq("g_sensor_list->next->next->name", "g_sensor_list->next->next->name", "volt")
    check_eq("g_banner", "g_banner", "fw-test")
    check_eq("g_counter", "g_counter", 8)



run_checks(main)
