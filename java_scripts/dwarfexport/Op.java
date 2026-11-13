package dwarfexport;

import ghidra.program.model.pcode.PcodeOp;

/** A p-code op decoded once: opcode, output and up to three inputs. */
public final class Op {
    public final int opc;
    public final Vn out, i0, i1, i2;

    public Op(int opc, Vn out, Vn i0, Vn i1, Vn i2) {
        this.opc = opc;
        this.out = out;
        this.i0 = i0;
        this.i1 = i1;
        this.i2 = i2;
    }

    public static Op decode(PcodeOp op) {
        int n = op.getNumInputs();
        return new Op(op.getOpcode(), Vn.decode(op.getOutput()), n > 0 ? Vn.decode(op.getInput(0)) : null,
            n > 1 ? Vn.decode(op.getInput(1)) : null, n > 2 ? Vn.decode(op.getInput(2)) : null);
    }
}
