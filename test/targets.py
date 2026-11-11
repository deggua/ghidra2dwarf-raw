"""Test targets: how to build the test firmware, import it into Ghidra, and
run it under QEMU for each architecture.

Every target except ppc32 runs as a static Linux binary under QEMU user mode
(qemu-<arch> -g PORT fw.elf). Ghidra still only sees the raw bytes
(objcopy -O binary) imported with the BinaryLoader at the link address, so
the export is exercised exactly as for a raw firmware dump. ppc32 runs as a
real boot ROM under qemu-system-ppc (mac99).

Compiler flags are chosen to match the ABI variant Ghidra's compiler spec
models (e.g. hard-float ARM, SVR4 struct returns on PPC32); see README.
"""

COMMON_CFLAGS = ["-g", "-ffreestanding", "-fno-builtin", "-fno-inline", "-fno-pic",
                 "-fno-asynchronous-unwind-tables", "-fno-unwind-tables",
                 "-fno-stack-protector", "-Wall", "-Wextra", "-Wno-unused-parameter"]
COMMON_LDFLAGS = ["-nostdlib", "-static", "-Wl,--build-id=none", "-Wl,--no-warn-rwx-segments",
                  "-Wl,-z,norelro", "-Wl,-z,noexecstack"]

BASE32 = 0x00400000
BASE64 = 0x10000000


def _t(**kw):
    kw.setdefault("cflags", [])
    kw.setdefault("asflags", [])
    kw.setdefault("ldflags", [])
    kw.setdefault("cspec", "default")
    kw.setdefault("mode", "user")
    kw.setdefault("thumb", False)
    kw.setdefault("qemu_args", [])
    kw.setdefault("irq", False)
    kw.setdefault("elfv2", False)
    kw.setdefault("sret_memory", False)   # small structs returned via hidden pointer
    return kw


TARGETS = {
    # --- PowerPC ---------------------------------------------------------------
    # MPC8245-class: PowerPC 603e core, boot ROM with exception vectors
    "ppc32": _t(cross="powerpc-linux-gnu-", isa="ppc32", mode="rom", base=0xFFF00000, irq=True,
                cflags=["-mcpu=603e", "-mhard-float", "-msdata=none", "-G0", "-msvr4-struct-return",
                        "-mno-relocatable"],
                asflags=["-mcpu=603e", "-Wa,-mregnames"],
                lang="PowerPC:BE:32:default", qemu_args=["-cpu", "603e"]),
    "ppc64be": _t(cross="powerpc64-linux-gnu-", isa="ppc64", base=BASE64, elfv2=True,
                  cflags=["-mabi=elfv2", "-mcmodel=medium"], asflags=["-mabi=elfv2"],
                  lang="PowerPC:BE:64:A2ALT", qemu="qemu-ppc64"),
    # ELFv1: function descriptors in .opd (traditional big-endian PPC64)
    "ppc64be-elfv1": _t(cross="powerpc64-linux-gnu-", isa="ppc64v1", base=BASE64, sret_memory=True,
                        cflags=["-mabi=elfv1", "-mcmodel=medium"], asflags=["-mabi=elfv1"],
                        lang="PowerPC:BE:64:A2ALT", qemu="qemu-ppc64"),
    "ppc64le": _t(cross="powerpc64le-linux-gnu-", isa="ppc64", base=BASE64, elfv2=True,
                  cflags=["-mcmodel=medium"], lang="PowerPC:LE:64:A2ALT", qemu="qemu-ppc64le"),
    # --- MIPS ----------------------------------------------------------------------
    "mips32be": _t(cross="mips-linux-gnu-", isa="mips", base=BASE32,
                   cflags=["-mno-abicalls", "-G0", "-march=mips32r2"], asflags=["-mno-abicalls", "-fno-pic", "-march=mips32r2"],
                   lang="MIPS:BE:32:default", qemu="qemu-mips"),
    "mips32le": _t(cross="mipsel-linux-gnu-", isa="mips", base=BASE32,
                   cflags=["-mno-abicalls", "-G0", "-march=mips32r2"], asflags=["-mno-abicalls", "-fno-pic", "-march=mips32r2"],
                   lang="MIPS:LE:32:default", qemu="qemu-mipsel"),
    "mips64be": _t(cross="mips64-linux-gnuabi64-", isa="mips", base=BASE64,
                   cflags=["-mno-abicalls", "-G0", "-march=mips64r2"], asflags=["-mno-abicalls", "-fno-pic", "-march=mips64r2"],
                   lang="MIPS:BE:64:default", qemu="qemu-mips64"),
    "mips64le": _t(cross="mips64el-linux-gnuabi64-", isa="mips", base=BASE64,
                   cflags=["-mno-abicalls", "-G0", "-march=mips64r2"], asflags=["-mno-abicalls", "-fno-pic", "-march=mips64r2"],
                   lang="MIPS:LE:64:default", qemu="qemu-mips64el"),
    # --- ARM (hard-float AAPCS, as ARM.cspec) -------------------------------------
    "armle": _t(cross="arm-linux-gnueabi-", isa="arm", base=BASE32,
                cflags=["-marm", "-march=armv7-a", "-mfloat-abi=hard", "-mfpu=vfpv3-d16"],
                asflags=["-marm", "-march=armv7-a", "-mfloat-abi=hard", "-mfpu=vfpv3-d16"],
                lang="ARM:LE:32:v7", qemu="qemu-arm", qemu_args=["-cpu", "cortex-a15"]),
    "armle-thumb": _t(cross="arm-linux-gnueabi-", isa="arm", base=BASE32, thumb=True,
                      cflags=["-mthumb", "-march=armv7-a", "-mfloat-abi=hard", "-mfpu=vfpv3-d16"],
                      asflags=["-mthumb", "-march=armv7-a", "-mfloat-abi=hard", "-mfpu=vfpv3-d16"],
                      lang="ARM:LE:32:v7", qemu="qemu-arm", qemu_args=["-cpu", "cortex-a15"]),
    "armbe": _t(cross="arm-linux-gnueabi-", isa="arm", base=BASE32,
                cflags=["-marm", "-march=armv7-a", "-mbig-endian", "-mfloat-abi=hard", "-mfpu=vfpv3-d16"],
                asflags=["-marm", "-march=armv7-a", "-mbig-endian", "-mfloat-abi=hard", "-mfpu=vfpv3-d16"],
                ldflags=["-mbig-endian", "-Wl,--be8"],
                lang="ARM:LEBE:32:v7LEInstruction", qemu="qemu-armeb", qemu_args=["-cpu", "cortex-a15"]),
    # --- AArch64 ---------------------------------------------------------------------
    "aarch64le": _t(cross="aarch64-linux-gnu-", isa="aarch64", base=BASE64,
                    lang="AARCH64:LE:64:v8A", qemu="qemu-aarch64"),
    "aarch64be": _t(cross="aarch64-linux-gnu-", isa="aarch64", base=BASE64,
                    cflags=["-mbig-endian"], asflags=["-mbig-endian"], ldflags=["-mbig-endian", "-Wl,-EB"],
                    lang="AARCH64:BE:64:v8A", qemu="qemu-aarch64_be"),
    # --- x86 ---------------------------------------------------------------------------
    "i386": _t(cross="", isa="x86_32", base=BASE32, cflags=["-m32", "-fno-pie"], asflags=["-m32"],
               ldflags=["-m32", "-no-pie"], lang="x86:LE:32:default", cspec="gcc", qemu="qemu-i386"),
    "x86_64": _t(cross="", isa="x86_64", base=BASE64, cflags=["-m64", "-fno-pie"],
                 asflags=["-m64"], ldflags=["-m64", "-no-pie"],
                 lang="x86:LE:64:default", cspec="gcc", qemu="qemu-x86_64"),
}
