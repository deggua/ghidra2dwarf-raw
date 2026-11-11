"""Machine-level data flow over raw p-code, shared by CFI generation and
variable location tracking.

For every instruction of a function we compute the abstract machine state on
entry to that instruction:

  * the stack pointer, as ``("sp", delta)`` = entry SP + delta;
  * for every register and every known stack slot, an abstract *value id*:
      ("init", reg)          the register's value at function entry
      ("def", addr, loc)     whatever instruction ``addr`` wrote to ``loc``
      ("phi", addr, loc)     a merge of different values at join ``addr``
      ("const", c, size)     a known constant
      ("sp", delta)          an address relative to the entry SP
  * the set of registers whose entry value has been saved to a stack slot
    (callee-saved registers, return address), for CFI.

Copies, register<->stack spills/reloads and SP arithmetic propagate value
ids, so after ``mr r31,r3`` both r3 and r31 hold ``init(r3)``, and after a
call only the call-preserved registers keep their ids. The decompiler only
tells us *which value* a variable has at a PC (it copy-propagates away the
physical moves); this analysis tells us *where that value physically is*.
"""

from ghidra.program.model.pcode import PcodeOp

from . import consts as C
from .dwarf import uleb, sleb, CommonInformation, FrameDescription

SP = "sp"
INIT = "init"
DEF = "def"
PHI = "phi"
CONST = "const"

MAX_STEPS = 500000


# ----------------------------------------------------------------------------
# Target description
# ----------------------------------------------------------------------------

# Link register per Ghidra processor, for compiler specs that don't declare
# <returnaddress>.
_LINK_REGISTERS = {
    "PowerPC": "LR",
    "ARM": "lr",
    "AARCH64": "x30",
    "MIPS": "ra",
    "RISCV": "ra",
    "SuperH": "pr",
    "SuperH4": "pr",
    "Xtensa": "a0",
}


# Registers holding an interrupted context's PC, per Ghidra processor, with
# the CFI return-address column used for them. GDB maps none of these DWARF
# numbers to a register (DWARF can't name them for GDB); a CIE's return
# address column needn't be a register GDB knows, and the rule for it is
# always "saved at a stack slot".
_IRQ_RETURN_REGS = {
    "PowerPC": [("SRR0", 100 + 26), ("CSRR0", 100 + 58), ("MCSRR0", 100 + 570)],
    "MIPS": [("EPC", 80), ("ErrorEPC", 81)],
    "AARCH64": [("elr_el1", 33), ("elr_el2", 34), ("elr_el3", 35)],
}


def _pc_column(lang):
    proc = str(lang.getProcessor())
    size = lang.getDefaultSpace().getPointerSize()
    if proc == "x86":
        return 16 if size == 8 else 8
    return None


class MachineInfo(object):
    """Calling-convention facts needed by the flow analysis."""

    def __init__(self, program, reg_index, stackshift, log=print):
        self.program = program
        self.listing = program.getListing()
        self.lang = program.getLanguage()
        self.regs = reg_index
        self.stackshift = stackshift
        self.log = log
        self.ptr_size = program.getDefaultPointerSize()

        cspec = program.getCompilerSpec()
        sp_reg = cspec.getStackPointer()
        self.sp_key = (int(sp_reg.getAddress().getOffset()), int(sp_reg.getMinimumByteSize()))
        self.sp_dwarf = self.dwarf_of(self.sp_key)

        cc = cspec.getDefaultCallingConvention()
        self.unaffected = set()
        if cc is not None:
            for vn in cc.getUnaffectedList():
                if vn.isRegister():
                    self.unaffected.add((int(vn.getOffset()), int(vn.getSize())))

        self.ra_key = None
        self.ra_stack = None
        ra = cc.getReturnAddress() if cc is not None else None
        if ra is not None and len(ra) == 1:
            vn = ra[0]
            if vn.isRegister():
                self.ra_key = (int(vn.getOffset()), int(vn.getSize()))
            elif vn.getAddress().isStackAddress():
                self.ra_stack = int(vn.getOffset())
        if self.ra_key is None and self.ra_stack is None:
            name = _LINK_REGISTERS.get(str(self.lang.getProcessor()))
            reg = self.lang.getRegister(name) if name else None
            if reg is not None:
                self.ra_key = (int(reg.getAddress().getOffset()), int(reg.getMinimumByteSize()))
        self.ra_dwarf = self.dwarf_of(self.ra_key) if self.ra_key is not None else _pc_column(self.lang)

        # Every register with a DWARF number.
        self.big_endian = bool(self.lang.isBigEndian())
        self.mapped = [(start, size) for start, size, _ in reg_index.entries]
        # Interrupt return registers: [((off, size), cfi column)].
        self.irq_ret = []
        for name, col in _IRQ_RETURN_REGS.get(str(self.lang.getProcessor()), []):
            reg = self.lang.getRegister(name)
            if reg is not None:
                self.irq_ret.append(((int(reg.getAddress().getOffset()), int(reg.getMinimumByteSize())), col))
        self.volatile = [k for k in self.mapped
                         if k != self.sp_key and k not in self.unaffected and k != self.ra_key]

    def dwarf_of(self, key):
        """DWARF number of the register exactly matching key, else None."""
        if key is None or len(key) != 2 or not isinstance(key[0], int):
            return None
        try:
            return self._dwarf_cache[key]
        except KeyError:
            pass
        except AttributeError:
            self._dwarf_cache = {}
        num = None
        hit = self.regs.lookup(key[0], key[1])
        if hit is not None and hit[1] == key[0] and hit[2] == key[1]:
            num = hit[0]
        self._dwarf_cache[key] = num
        return num

    def containers(self, key):
        """Mapped registers strictly containing register bytes ``key``."""
        try:
            return self._containers[key]
        except KeyError:
            pass
        except AttributeError:
            self._containers = {}
        out = [mk for mk in self.mapped
               if mk != key and mk[0] <= key[0] and key[0] + key[1] <= mk[0] + mk[1]]
        self._containers[key] = out
        return out

    def stack_purge(self, target):
        """Bytes the callee at `target` pops (beyond the return address)."""
        if target is None:
            return 0
        off = int(target.getOffset())
        cache = getattr(self, "_purge", None)
        if cache is None:
            cache = self._purge = {}
        if off not in cache:
            f = self.program.getFunctionManager().getFunctionAt(target)
            p = int(f.getStackPurgeSize()) if f is not None else 0
            cache[off] = p if 0 < p < 0x10000 else 0
        return cache[off]

    def is_preserved(self, key):
        """Is the register (or the register containing it) preserved across
        calls, so that CFI can unwind it in caller frames?"""
        if key == self.sp_key or key in self.unaffected:
            return True
        return any(c in self.unaffected for c in self.containers(key))


# ----------------------------------------------------------------------------
# Abstract state
# ----------------------------------------------------------------------------

class State(object):
    __slots__ = ("regs", "mem", "saved")

    def __init__(self, regs=None, mem=None, saved=None):
        self.regs = regs if regs is not None else {}     # (off,size) -> value
        self.mem = mem if mem is not None else {}        # sp offset -> (size, value)
        self.saved = saved if saved is not None else {}  # (off,size) -> sp offset

    def copy(self):
        return State(dict(self.regs), dict(self.mem), dict(self.saved))

    def __eq__(self, other):
        return self.regs == other.regs and self.mem == other.mem and self.saved == other.saved

    def __ne__(self, other):
        return not self.__eq__(other)


def _signed(c, size):
    bits = 8 * size
    c &= (1 << bits) - 1
    return c - (1 << bits) if c >> (bits - 1) else c


class FunctionFlow(object):
    """Runs the analysis for one function. After construction:

    ``insns``      sorted list of instruction offsets in the body
    ``state_in``   {offset: State} on entry to each reachable instruction
    ``state_out``  {offset: State} after each reachable instruction
    """

    def __init__(self, machine, func):
        self.m = machine
        self.func = func
        self.listing = machine.listing
        self.state_in = {}
        self.state_out = {}
        self.insn_len = {}
        self.insns = []
        self.converged = True
        self._run()

    # -- value access ------------------------------------------------------------
    def default(self, key):
        sp = self.m.sp_key
        if key == sp:
            return (SP, 0)
        if (isinstance(key[0], int) and sp[0] <= key[0] and key[0] + key[1] <= sp[0] + sp[1]
                and self._is_low_part(key, sp)):
            return (SP, 0)   # low half of a 64-bit SP (n32 address arithmetic)
        return (INIT, key)

    def _is_low_part(self, k, c):
        """Is register bytes k the low-order part of register c?"""
        if self.m.big_endian:
            return k[0] + k[1] == c[0] + c[1]
        return k[0] == c[0]

    @staticmethod
    def _rekey(value, key):
        """The same value id, for another (narrower or wider) view."""
        t = value[0]
        if t == INIT:
            return (INIT, key)
        if t in (DEF, PHI):
            return (t, value[1], key)
        return None

    def _narrow(self, value, size):
        """Value id of the low-order `size` bytes of `value`."""
        if value is None or size <= 0:
            return None
        t = value[0]
        if t == SP:
            # addresses: n32/x32 compute SP-relative addresses in the low
            # 32 bits of 64-bit registers
            return value
        key = value[1] if t == INIT else (value[2] if t in (DEF, PHI) else None)
        if t == CONST:
            return (CONST, value[1] & ((1 << (8 * size)) - 1), size)
        if not (isinstance(key, tuple) and len(key) == 2 and isinstance(key[0], int)):
            return None
        if size >= key[1]:
            return value
        lo = key[0] + (key[1] - size if self.m.big_endian else 0)
        return self._rekey(value, (lo, size))

    def reg_value(self, st, key):
        if key in st.regs:
            return st.regs[key]
        for rk in st.regs:
            if rk[0] != "u" and rk[0] < key[0] + key[1] and key[0] < rk[0] + rk[1]:
                # Overwritten through another view. If a containing register
                # was written, its low part has a value of the same origin
                # (e.g. AArch64 "add w0,.." writes X0 = zext(result)).
                v = st.regs[rk]
                if (v is not None and rk[0] <= key[0] and key[0] + key[1] <= rk[0] + rk[1]
                        and self._is_low_part(key, rk)):
                    # the low part of the *value's* origin (v0 = copy of a0:
                    # v0's low half holds a0's low half)
                    return self._narrow(v, key[1])
                return None
        return self.default(key)

    # Varnodes are decoded once into tuples: ("c", value, size),
    # ("r", offset, size), ("u", offset, size) or ("x",) for other spaces.
    @staticmethod
    def _decode(vn):
        if vn is None:
            return None
        if vn.isConstant():
            return ("c", int(vn.getOffset()), int(vn.getSize()))
        if vn.isRegister():
            return ("r", int(vn.getOffset()), int(vn.getSize()))
        if vn.isUnique():
            return ("u", int(vn.getOffset()), int(vn.getSize()))
        return ("x",)

    def _get(self, st, d):
        t = d[0]
        if t == "c":
            return (CONST, d[1], d[2])
        if t == "r":
            return self.reg_value(st, (d[1], d[2]))
        if t == "u":
            return st.regs.get(d)
        return None

    def _set(self, st, d, value, ins_off):
        t = d[0]
        if t == "r":
            k = (d[1], d[2])
            if value is None:
                value = (DEF, ins_off, k)
            for other in [o for o in st.regs if o[0] != "u" and o != k
                          and o[0] < k[0] + k[1] and k[0] < o[0] + o[1]]:
                if k[0] <= other[0] and other[0] + other[1] <= k[0] + k[1]:
                    # a view inside the written register: reg_value derives
                    # it from the new value (n32: SP's low half after "move sp,s8")
                    del st.regs[other]
                else:
                    st.regs[other] = None
            # Registers that contain the written one also change.
            for mk in self.m.containers(k):
                if mk not in st.regs:
                    st.regs[mk] = None
            st.regs[k] = value
        elif t == "u":
            st.regs[d] = value

    def _arith(self, opc, a, b):
        if a is None or b is None:
            return None
        # Identities used for register moves (PPC "mr" is "or rD,rS,rS",
        # "addi rD,rS,0", "ori rD,rS,0", ...).
        if opc in (PcodeOp.INT_OR, PcodeOp.INT_AND) and a == b:
            return a
        if opc in (PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.INT_ADD, PcodeOp.INT_SUB,
                   PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT):
            # x op 0 == x (MIPS64 canonicalizes 32-bit values with "sll v,v,0")
            if b[0] == CONST and b[1] == 0:
                return a
            if a[0] == CONST and a[1] == 0 and opc != PcodeOp.INT_SUB:
                return b
        if opc == PcodeOp.INT_ADD:
            if a[0] == SP and b[0] == CONST:
                return (SP, a[1] + _signed(b[1], b[2]))
            if b[0] == SP and a[0] == CONST:
                return (SP, b[1] + _signed(a[1], a[2]))
            if a[0] == CONST and b[0] == CONST:
                return (CONST, (a[1] + b[1]) & ((1 << (8 * a[2])) - 1), a[2])
        elif opc == PcodeOp.INT_SUB:
            if a[0] == SP and b[0] == CONST:
                return (SP, a[1] - _signed(b[1], b[2]))
        return None

    # -- transfer function ---------------------------------------------------------
    _ARITH = (PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_OR, PcodeOp.INT_AND, PcodeOp.INT_XOR,
              PcodeOp.INT_LEFT, PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT)

    def step(self, st, off):
        """Applies the instruction at offset ``off`` to ``st`` in place."""
        is_call, _, _, _, _, ops = self.decoded[off]
        sp_before = self.reg_value(st, self.m.sp_key)
        written = set()
        for opc, out, i0, i1, i2 in ops:
            if out is not None and out[0] == "r":
                written.add((out[1], out[2]))
            if opc == PcodeOp.STORE:
                addr = self._get(st, i1)
                if addr is not None and addr[0] == SP:
                    soff = addr[1]
                    size = i2[2] if len(i2) > 2 else 0
                    for o in [o for o, (sz, _) in st.mem.items() if o < soff + size and soff < o + sz]:
                        del st.mem[o]
                    val = self._get(st, i2)
                    st.mem[soff] = (size, val)
                    if (val is not None and val[0] == INIT and val[1] not in st.saved
                            and self.m.dwarf_of(val[1]) is not None):
                        st.saved[val[1]] = soff
                continue
            if out is None:
                continue
            if opc == PcodeOp.COPY:
                val = self._get(st, i0)
            elif opc in self._ARITH:
                val = self._arith(opc, self._get(st, i0), self._get(st, i1))
            elif opc == PcodeOp.LOAD:
                val = None
                addr = self._get(st, i1)
                if addr is not None and addr[0] == SP:
                    slot = st.mem.get(addr[1])
                    if slot is not None and len(out) > 2 and slot[0] == out[2]:
                        val = slot[1]
            elif opc == PcodeOp.SUBPIECE and i1 is not None and i1[0] == "c" and i1[1] == 0:
                # Low-order bytes of a value (e.g. MIPS64 "sw a0,.." stores
                # the 32-bit low part of the 64-bit a0): same origin, narrower.
                val = self._narrow(self._get(st, i0), out[2] if len(out) > 2 else 0)
            elif opc in (PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT) and out[0] == "r" and i0[0] in "ru":
                # Widening writes (x86-64 "mov ebx, edi" is RBX = zext(EBX),
                # MIPS64/PPC64 32-bit ops sign-extend): the wide register gets
                # a new value, but its low part still holds the narrow one.
                inner = self._get(st, i0)
                # an extended stack address is still that address (n32:
                # "addiu sp,sp,-16" = sext(sp:4 - 16))
                self._set(st, out, inner if (inner is not None and inner[0] == SP) else None, off)
                if inner is not None and i0[2] < out[2]:
                    lo = out[1] if not self.m.big_endian else out[1] + out[2] - i0[2]
                    st.regs[(lo, i0[2])] = inner
                continue
            else:
                val = None
            self._set(st, out, val, off)

        for k in [k for k in st.regs if k[0] == "u"]:
            del st.regs[k]

        if is_call:
            # The callee returns with the SP as before the call (plus any
            # arguments it pops itself: stdcall, -mrtd) and clobbers every
            # register that is not preserved across calls.
            if sp_before is not None:
                if sp_before[0] == SP:
                    purge = self.m.stack_purge(self.call_targets.get(off))
                    st.regs[self.m.sp_key] = (SP, sp_before[1] + purge)
                else:
                    st.regs[self.m.sp_key] = sp_before
            for k in self.m.volatile:
                st.regs[k] = (DEF, off, k)
            for k in list(st.regs):
                if k != self.m.sp_key and k not in self.m.unaffected and k not in self.m.volatile:
                    if k != self.m.ra_key:
                        st.regs[k] = (DEF, off, k)
            if self.m.ra_key is not None and self.m.ra_key in written:
                st.regs[self.m.ra_key] = (DEF, off, self.m.ra_key)

        # Registers reloaded with their entry value are "restored".
        for k in list(st.saved):
            if k in written and st.regs.get(k) == (INIT, k):
                del st.saved[k]

    # -- join ----------------------------------------------------------------
    def merge(self, a, b, join_off):
        regs = {}
        for k in set(a.regs) | set(b.regs):
            va = self.reg_value(a, k) if k[0] != "u" else a.regs.get(k)
            vb = self.reg_value(b, k) if k[0] != "u" else b.regs.get(k)
            if va == vb:
                regs[k] = va
            elif va is None or vb is None:
                regs[k] = None
            else:
                regs[k] = (PHI, join_off, k)
        mem = {}
        for o in set(a.mem) & set(b.mem):
            sa, va = a.mem[o]
            sb, vb = b.mem[o]
            if sa != sb:
                continue
            if va == vb:
                mem[o] = (sa, va)
            elif va is not None and vb is not None:
                mem[o] = (sa, (PHI, join_off, ("m", o)))
        saved = {k: v for k, v in a.saved.items() if b.saved.get(k) == v}
        return State(regs, mem, saved)

    def stabilize(self, old, new, join_off):
        """Keep a join's state monotone (concrete -> own phi -> unknown,
        dropped slots stay dropped) so the fixpoint iteration terminates:
        otherwise phis of nested loop heads can chase each other forever."""
        for k, ov in old.regs.items():
            nv = new.regs[k] if k in new.regs else (
                self.reg_value(new, k) if k[0] != "u" else None)
            if ov is None:
                new.regs[k] = None
            elif ov == (PHI, join_off, k) and nv is not None:
                new.regs[k] = ov
        for o in list(new.mem):
            if o not in old.mem:
                del new.mem[o]
            else:
                osz, ov = old.mem[o]
                nsz, nv = new.mem[o]
                if osz != nsz or ov is None:
                    new.mem[o] = (nsz, None) if osz == nsz else None
                    if new.mem[o] is None:
                        del new.mem[o]
                elif ov == (PHI, join_off, ("m", o)) and nv is not None:
                    new.mem[o] = (nsz, ov)
        new.saved = dict((k, v) for k, v in new.saved.items() if old.saved.get(k) == v)
        return new

    # -- driver ---------------------------------------------------------------
    def _run(self):
        func = self.func
        body = func.getBody()
        entry = func.getEntryPoint()

        dec = self._decode
        self.decoded = {}
        self.call_targets = {}
        for ins in self.listing.getInstructions(body, True):
            o = int(ins.getAddress().getOffset())
            self.insns.append(o)
            self.insn_len[o] = int(ins.getLength())
            ft = ins.getFlowType()
            ops = []
            for op in ins.getPcode():
                n = op.getNumInputs()
                ins_ = [dec(op.getInput(i)) if i < n else None for i in range(3)]
                ops.append((int(op.getOpcode()), dec(op.getOutput()), ins_[0], ins_[1], ins_[2]))
            if ft.isCall():
                tg = [t for t in ins.getFlows() if t is not None]
                if len(tg) == 1:
                    self.call_targets[o] = tg[0]
            succs = []
            if not ft.isTerminal():
                fall = ins.getFallThrough()
                if fall is not None and body.contains(fall):
                    succs.append(int(fall.getOffset()))
            if ft.isJump():
                for t in ins.getFlows():
                    if t is not None and body.contains(t):
                        succs.append(int(t.getOffset()))
            self.decoded[o] = (bool(ft.isCall()), bool(ft.isJump()), bool(ft.isTerminal()),
                               int(ins.getDelaySlotDepth()), succs, ops)
        self.insns.sort()

        init = State()
        if self.m.ra_stack is not None:
            init.mem[self.m.ra_stack] = (self.m.ptr_size, (INIT, ("ra",)))
        entry_off = int(entry.getOffset())
        self.state_in[entry_off] = init
        preds = {}
        work = [entry_off]
        queued = {entry_off}
        steps = 0
        while work:
            aoff = work.pop()
            queued.discard(aoff)
            steps += 1
            if steps > MAX_STEPS:
                self.converged = False
                self.m.log("WARNING: flow analysis of %s did not converge" % func.getName())
                break
            d = self.decoded.get(aoff)
            if d is None:
                continue
            st = self.state_in[aoff].copy()
            self.step(st, aoff)
            self.state_out[aoff] = st
            for k in d[4]:
                preds.setdefault(k, set()).add(aoff)
                # In-state = join of all predecessors' current out-states.
                new = None
                for p in sorted(preds[k]):
                    ps = self.state_out.get(p)
                    if ps is None:
                        continue
                    new = ps if new is None else self.merge(new, ps, k)
                if k == entry_off:
                    new = self.merge(init, new, k)
                old = self.state_in.get(k)
                if old is not None and len(preds[k]) > 1:
                    new = self.stabilize(old, new, k)
                if old is None or new != old:
                    self.state_in[k] = new
                    if k not in queued:
                        queued.add(k)
                        work.append(k)

        # Delay slots (MIPS, SPARC, ...): Ghidra folds the slot instruction's
        # p-code into the branch, so the slot is never stepped on its own.
        # PCs inside a slot are almost only seen as a caller frame's
        # "return address - 1", i.e. after the slot (and the call) took
        # effect: use the branch's out-state ("jal f; addiu s0,s0,1" means
        # s0 no longer holds the old value while f runs).
        for i, o in enumerate(self.insns):
            depth = self.decoded[o][3]
            if depth and o in self.state_in:
                after = self.state_out.get(o, self.state_in[o])
                for ds in self.insns[i + 1:i + 1 + depth]:
                    if ds not in self.state_in:
                        self.state_in[ds] = after
                        self.state_out[ds] = after

    # -- prologue ---------------------------------------------------------------
    def _is_prologue_insn(self, ins, st_in):
        """True if the instruction only sets up the frame: adjusts SP, saves
        entry register values / the back chain to the stack, or copies the
        return address register."""
        st = st_in.copy()
        self.step(st, int(ins.getAddress().getOffset()))
        for k in set(st.regs) | set(st_in.regs):
            if k[0] == "u" or self.m.dwarf_of(k) is None and not self.m.containers(k):
                # scratch / pseudo registers (ARM mult_addr, flags): not
                # program state a debugger shows
                continue
            before = st_in.regs[k] if k in st_in.regs else self.default(k)
            after = st.regs[k] if k in st.regs else self.default(k)
            if before == after:
                continue
            if k == self.m.sp_key and after is not None and after[0] == SP:
                continue
            if self.m.ra_key is not None and after == (INIT, self.m.ra_key):
                continue
            return False
        for o, (size, v) in st.mem.items():
            if st_in.mem.get(o) == (size, v):
                continue
            if v is None or v[0] not in (INIT, SP):
                return False
        return True

    def prologue_end(self, skip=0):
        """Offset of the first instruction after the frame setup (the entry
        point itself for frameless functions). ``skip`` bytes at the entry
        are always prologue (e.g. the PPC64 ELFv2 global-entry TOC setup)."""
        entry = int(self.func.getEntryPoint().getOffset())
        off = entry + skip
        addr = self.func.getEntryPoint().add(skip)
        while True:
            st = self.state_in.get(off)
            ins = self.listing.getInstructionAt(addr)
            if st is None or ins is None:
                break
            ft = ins.getFlowType()
            if ft.isJump() or ft.isCall() or ft.isTerminal() or ins.getDelaySlotDepth() > 0:
                break
            if not self._is_prologue_insn(ins, st):
                break
            nxt = ins.getFallThrough()
            if nxt is None or not self.func.getBody().contains(nxt):
                break
            addr = nxt
            off = int(nxt.getOffset())
        return off

    # -- queries ----------------------------------------------------------------
    def insn_end(self, off):
        return off + self.insn_len.get(off, 1)

    def value_after(self, off, key):
        st = self.state_out.get(off)
        return self.reg_value(st, key) if st is not None else None

    def value_before(self, off, key):
        st = self.state_in.get(off)
        return self.reg_value(st, key) if st is not None else None

    def locations_of(self, off, value):
        """All (kind, where) holding ``value`` on entry to instruction off:
        ("reg", key) or ("stack", sp_offset)."""
        st = self.state_in.get(off)
        if st is None or value is None:
            return []
        out = []
        for k, v in st.regs.items():
            if v == value and k[0] != "u":
                out.append(("reg", k))
        # A narrow value also lives in the low part of any register holding
        # the wider value of the same origin (MIPS64 "move s0,a0" copies the
        # 64-bit a0 while the variable is its 32-bit low part).
        vkey = value[1] if value[0] == INIT else (value[2] if value[0] in (DEF, PHI) else None)
        if isinstance(vkey, tuple) and len(vkey) == 2 and isinstance(vkey[0], int):
            for c in self.m.containers(vkey):
                if not self._is_low_part(vkey, c):
                    continue
                wide = self._rekey(value, c)
                for k, v in st.regs.items():
                    if v == wide and k[0] != "u" and k[1] == c[1]:
                        lo = k[0] + (k[1] - vkey[1] if self.m.big_endian else 0)
                        out.append(("reg", (lo, vkey[1])))
                if wide == (INIT, c) and c not in st.regs and self.reg_value(st, c) == wide:
                    lo = c[0] + (c[1] - vkey[1] if self.m.big_endian else 0)
                    out.append(("reg", (lo, vkey[1])))
        if value[0] == INIT and value[1] not in st.regs and isinstance(value[1][0], int):
            # untouched register still holding its entry value (unless a
            # containing/contained register was written)
            if self.reg_value(st, value[1]) == value:
                out.append(("reg", value[1]))
        for o, (s, v) in st.mem.items():
            if v == value:
                out.append(("stack", o))
        return out


# ----------------------------------------------------------------------------
# CFI
# ----------------------------------------------------------------------------

class CfiGenerator(object):
    """Emits a CIE and per-function FDEs from FunctionFlow states."""

    def __init__(self, machine, dwarf_builder, address_mapper, entry_points=(), irq_signal_frame=True):
        self.irq_signal_frame = irq_signal_frame
        self.m = machine
        self.dw = dwarf_builder
        self.A = address_mapper
        self.entry_points = set(entry_points)
        self.ok = False
        if machine.sp_dwarf is None:
            machine.log("WARNING: stack pointer has no DWARF register number; no CFI generated")
            return
        if machine.ra_dwarf is None:
            machine.log("WARNING: cannot determine the return address register; no CFI generated")
            return
        init = bytearray()
        init.append(C.DW_CFA_def_cfa)
        init += uleb(machine.sp_dwarf) + uleb(machine.stackshift)
        if machine.ra_stack is not None:
            init.append(C.DW_CFA_offset_extended_sf)
            init += uleb(machine.ra_dwarf) + sleb(machine.ra_stack - machine.stackshift)
        # Call-clobbered registers do not survive into the caller's frame:
        # say so, so GDB shows <not saved> instead of the callee's values.
        for k in machine.volatile:
            num = machine.dwarf_of(k)
            if num is not None and num != machine.ra_dwarf:
                init.append(C.DW_CFA_undefined)
                init += uleb(num)
        dwarf_builder.cie = CommonInformation(1, 1, machine.ra_dwarf, bytes(init))
        self._irq_cies = {}
        self.ok = True

    def _irq_cie(self, col):
        """CIE for interrupt handlers returning through `col` (e.g. SRR0):
        a signal frame ("S"), every register preserved, and the return
        address unknown until the handler stores it."""
        idx = self._irq_cies.get(col)
        if idx is None:
            m = self.m
            init = bytearray()
            init.append(C.DW_CFA_def_cfa)
            init += uleb(m.sp_dwarf) + uleb(m.stackshift)
            init.append(C.DW_CFA_undefined)
            init += uleb(col)
            idx = self.dw.add_cie(CommonInformation(1, 1, col, bytes(init),
                                                    augmentation="S" if self.irq_signal_frame else ""))
            self._irq_cies[col] = idx
        return idx

    def _rule(self, flow, st, irq=None):
        m = self.m
        cfa = None
        sp = flow.reg_value(st, m.sp_key)
        if sp is not None and sp[0] == SP:
            cfa = (m.sp_dwarf, m.stackshift - sp[1])
        else:
            for k, v in sorted((kv for kv in st.regs.items() if kv[0][0] != "u"), key=lambda kv: kv[0]):
                if v is not None and v[0] == SP:
                    num = m.dwarf_of(k)
                    if num is not None:
                        cfa = (num, m.stackshift - v[1])
                        break
        if cfa is None:
            return None
        # Derive the save rules from the state at this PC: a call-preserved
        # register (or the return address register) that no longer holds its
        # entry value is recoverable from a stack slot holding that value.
        # (Bookkeeping "saved"/"restored" events is wrong when a reload and a
        # later clobber meet at a join, e.g. MIPS loops reloading ra in a
        # delay slot and calling again.)
        slots = {}
        for o, (size, v) in st.mem.items():
            if v is not None and v[0] == INIT and v[1] not in slots:
                slots[v[1]] = (o, size)
        saved = {}
        if irq is not None:
            # Interrupt handler: the interrupted code expects *every*
            # register back, and its PC is in the interrupt return register
            # until the handler stores it.
            ret_key, col = irq
            slot = slots.get(ret_key)
            if slot is not None and slot[1] == ret_key[1]:
                saved[col] = slot[0] - m.stackshift
            for k in m.mapped:
                num = m.dwarf_of(k)
                if num is None or k == m.sp_key:
                    continue
                # Use the slot whenever there is one: calls made by the
                # handler clobber volatile registers, and a caller-frame
                # lookup happens inside the call instruction.
                slot = slots.get(k)
                if slot is not None and slot[1] == k[1]:
                    saved[num] = slot[0] - m.stackshift
            return cfa[0], cfa[1], saved
        for k in self._tracked_regs():
            num = m.dwarf_of(k)
            if num is None or k == m.sp_key:
                continue
            slot = slots.get(k)
            if slot is not None and slot[1] != k[1]:
                slot = None
            holds_entry = flow.reg_value(st, k) == (INIT, k)
            if k == m.ra_key:
                # Calls clobber the return address register, and GDB looks
                # up a caller frame's rules inside its call instruction: use
                # the save slot whenever there is one.
                if slot is not None:
                    saved[num] = slot[0] - m.stackshift
            elif not holds_entry and slot is not None:
                # Callee-saved registers survive calls; only once clobbered
                # is the slot the place to find them.
                saved[num] = slot[0] - m.stackshift
        return cfa[0], cfa[1], saved

    def _tracked_regs(self):
        if not hasattr(self, "_tracked"):
            m = self.m
            keys = [k for k in m.unaffected if m.dwarf_of(k) is not None]
            if m.ra_key is not None:
                keys.append(m.ra_key)
            self._tracked = sorted(set(keys))
        return self._tracked

    @staticmethod
    def _encode(prev, cur, undefined_cols=()):
        ops = bytearray()
        if prev is None or (prev[0], prev[1]) != (cur[0], cur[1]):
            if cur[1] >= 0:
                if prev is not None and prev[0] == cur[0]:
                    ops.append(C.DW_CFA_def_cfa_offset)
                    ops += uleb(cur[1])
                else:
                    ops.append(C.DW_CFA_def_cfa)
                    ops += uleb(cur[0]) + uleb(cur[1])
            else:
                ops.append(0x12)  # DW_CFA_def_cfa_sf (data_align = 1)
                ops += uleb(cur[0]) + sleb(cur[1])
        prev_saved = prev[2] if prev is not None else {}
        for reg, off in sorted(cur[2].items()):
            if prev_saved.get(reg) != off:
                ops.append(C.DW_CFA_offset_extended_sf)
                ops += uleb(reg) + sleb(off)
        for reg in sorted(prev_saved):
            if reg not in cur[2]:
                ops.append(C.DW_CFA_undefined if reg in undefined_cols else C.DW_CFA_same_value)
                ops += uleb(reg)
        return bytes(ops)

    def _irq_return_reg(self, flow):
        """The interrupt return register this handler saves (else the first
        one the processor has)."""
        for key, col in self.m.irq_ret:
            for st in flow.state_in.values():
                if any(v == (INIT, key) for _, v in st.mem.values()):
                    return key, col
        return self.m.irq_ret[0] if self.m.irq_ret else None

    def add_function(self, flow, ranges, interrupt=False):
        if not self.ok:
            return
        m = self.m
        irq = self._irq_return_reg(flow) if interrupt else None
        cie = self._irq_cie(irq[1]) if irq is not None else 0
        undefined_cols = (irq[1],) if irq is not None else ()
        outermost = irq is None and int(flow.func.getEntryPoint().getOffset()) in self.entry_points
        for lo, hi in ranges:
            rows = []
            prev = (m.sp_dwarf, m.stackshift, {})
            if outermost:
                # Program entry point: there is no caller to unwind to.
                rows.append((self.A(lo), bytes([C.DW_CFA_undefined]) + uleb(m.ra_dwarf)))
            for off in flow.insns:
                if off < lo or off >= hi:
                    continue
                st = flow.state_in.get(off)
                if st is None:
                    continue
                rule = self._rule(flow, st, irq)
                if rule is None:
                    continue
                ops = self._encode(prev, rule, undefined_cols)
                if ops:
                    rows.append((self.A(off), ops))
                prev = rule
            self.dw.fdes.append(FrameDescription(self.A(lo), self.A(lo) + (hi - lo), rows, cie))
