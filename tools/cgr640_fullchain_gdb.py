# CGR640 full-chain capture for QEMU gdbstub / GDB
# Run while provider_cgr640.exe is stopped at 0x004014c0.
# This script only ARMS breakpoints. It does not resume execution.

import gdb
import json
import os
import struct
import time

TARGET_CR3 = 0x15A0E000
OUTDIR = "/home/hal/xp-cgr-lab/evidence/cgr640-full-01"
EVENTS = os.path.join(OUTDIR, "events.jsonl")

KSEC_GLOBAL = 0xF77344E0

ADDR = {
    "B01": 0xF7738951, "B02": 0xF77389A6, "B03": 0xF77389C8,
    "K00": 0xF77383D6, "K01": 0xF773842F, "K02": 0xF773844B,
    "K03": 0xF7738490, "K04": 0xF77384BD, "K05": 0xF77384F5,
    "K06": 0xF7738550, "K07": 0xF7738583, "K08": 0xF77385B9,
    "K09": 0xF77385EC, "K10": 0xF773861F, "K11": 0xF773864E,
    "K12": 0xF77386A5, "K13": 0xF77386E6, "K14": 0xF7738724,
    "K15": 0xF7738758, "K16": 0xF7738786, "K17": 0xF77387AA,
    "B04": 0x77DA9549, "B05": 0x77DA8292, "B06": 0x77DA82A6,
    "B07": 0x77DA8633, "B08": 0x77DA8623,
    "B09": 0x6800D7D5,
    "B10": 0x6800D693,
    "B11": 0x6800D69E,
    "B12": 0x68027101,
    "B13": 0x6800D6FB,
    "B14": 0x6800D7DA,
    "CPGEN": 0x6800D7A7,
}

os.makedirs(OUTDIR, exist_ok=True)
with open(EVENTS, "w", encoding="utf-8"):
    pass

_seq = 0
_state = {
    "ksec": {}, "sys": {}, "prga": {}, "fips": {}, "provider": {},
    "rsaenh_armed": False, "provider_bps": [], "last_b10_sig": None,
    "d640_call_id": 0, "accepted_blocks": 0,
}

def _ival(expr):
    return int(gdb.parse_and_eval(expr))

def reg(name):
    return _ival("$" + name) & 0xFFFFFFFF

def read_mem(addr, size):
    if addr is None or size <= 0:
        return b""
    try:
        return bytes(gdb.selected_inferior().read_memory(addr, size))
    except gdb.error:
        return None

def read_u32(addr):
    data = read_mem(addr, 4)
    if data is None or len(data) != 4:
        return None
    return struct.unpack("<I", data)[0]

def hx(data):
    return None if data is None else data.hex()

def safe_dump(addr, size, cap=0x4000):
    if addr is None:
        return None
    size = max(0, min(int(size), cap))
    return hx(read_mem(addr, size))

def emit(kind, **fields):
    global _seq
    _seq += 1
    event = {
        "seq": _seq,
        "kind": kind,
        "host_time_ns": time.time_ns(),
        "eip": reg("eip"),
        "cr3": reg("cr3"),
    }
    event.update(fields)
    with open(EVENTS, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")

def target_context():
    try:
        return reg("cr3") == TARGET_CR3
    except gdb.error:
        return False

def common_regs():
    return {r: reg(r) for r in ("eax","ebx","ecx","edx","esi","edi","esp","ebp")}

class TraceBP(gdb.Breakpoint):
    def __init__(self, name, address, handler, hardware=False):
        bp_type = gdb.BP_HARDWARE_BREAKPOINT if hardware else gdb.BP_BREAKPOINT
        super().__init__(f"*0x{address:08x}", type=bp_type, internal=False)
        self.trace_name = name
        self.handler = handler

    def stop(self):
        if not target_context():
            return False
        try:
            return bool(self.handler())
        except Exception as exc:
            emit("CAPTURE_ERROR", breakpoint=self.trace_name, error=repr(exc),
                 regs=common_regs())
            gdb.write(f"\nCGR640_CAPTURE_ERROR {self.trace_name}: {exc}\n")
            return True

def h_b01():
    esp = reg("esp")
    outp = read_u32(esp + 8)
    outlen = read_u32(esp + 0xC)
    _state["ksec"] = {"outp": outp, "outlen": outlen}
    emit("B01_KSEC_NEWGEN_ENTRY", out_ptr=outp, out_len=outlen,
         out_before_hex=safe_dump(outp, 0x100), regs=common_regs())
    return False

def h_b02():
    k = _state["ksec"]
    emit("B02_KSEC_AFTER_GATHER", out_ptr=k.get("outp"), out_len=k.get("outlen"),
         out_hex=safe_dump(k.get("outp"), 0x100), regs=common_regs())
    return False

def h_b03():
    k = _state["ksec"]
    emit("B03_KSEC_PRE_RETURN", out_ptr=k.get("outp"), out_len=k.get("outlen"),
         out_hex=safe_dump(k.get("outp"), 0x100), regs=common_regs())
    return False

def h_k00():
    ebp = reg("ebp")
    inp = read_u32(ebp + 8)
    in_len = read_u32(ebp + 0xC)
    outp = read_u32(ebp + 0x10)
    outlenp = read_u32(ebp + 0x14)
    emit("K00_COLLECTOR_ALLOCATED",
         collector_base=reg("eax"), caller_input=inp, caller_input_len=in_len,
         output=outp, output_len_ptr=outlenp,
         caller_input_hex=safe_dump(inp, in_len or 0, cap=0x1000),
         regs=common_regs())
    return False

def h_k_source(name, size):
    def _h():
        ebp = reg("ebp")
        src = reg("esi")
        emit(name, source_start=src,
             collector_base=read_u32(ebp - 0x1D4),
             source_hex=safe_dump(src, size),
             reported_len=read_u32(ebp - 0x1D0),
             remaining=reg("ebx"), status=reg("eax"), regs=common_regs())
        return False
    return _h

def h_k_workspace(name):
    def _h():
        ebp = reg("ebp")
        base = read_u32(ebp - 0x1D4)
        emit(name, collector_base=base, source_start=reg("esi"),
             workspace_e00_hex=safe_dump(base, 0xE00),
             reported_len=read_u32(ebp - 0x1D0),
             remaining=reg("ebx"), status=reg("eax"), regs=common_regs())
        return False
    return _h

def h_k13():
    ebp = reg("ebp")
    base = read_u32(ebp - 0x1D4)
    emit("K13_PRE_MIX", collector_base=base, cursor=reg("esi"),
         remaining=reg("ebx"), used=(0xE00 - reg("ebx")) & 0xFFFFFFFF,
         global_state_before_50_hex=safe_dump(KSEC_GLOBAL, 0x50),
         workspace_pre_mix_e00_hex=safe_dump(base, 0xE00), regs=common_regs())
    return False

def h_k14():
    ebp = reg("ebp")
    emit("K14_POST_MIX", mixer_status=reg("eax"), remaining=reg("ebx"),
         state_after_mix_50_hex=safe_dump(ebp - 0x54, 0x50), regs=common_regs())
    return False

def h_k15():
    ebp = reg("ebp")
    emit("K15_OLD_STATE_RC4_RETURN",
         old_state_after_50_hex=safe_dump(ebp - 0xA4, 0x50),
         rc4_context_after_old_state_102_hex=safe_dump(ebp - 0x1CC, 0x102),
         regs=common_regs())
    return False

def h_k16():
    ebp = reg("ebp")
    emit("K16_FINAL_RC4_KSA",
         rc4_context_102_hex=safe_dump(ebp - 0x1CC, 0x102),
         global_state_50_hex=safe_dump(KSEC_GLOBAL, 0x50), regs=common_regs())
    return False

def h_k17():
    ebp = reg("ebp")
    outp = read_u32(ebp - 0x1DC)
    outlenp = read_u32(ebp - 0x1E0)
    outlen = read_u32(outlenp) if outlenp is not None else None
    emit("K17_FINAL_RC4_OUTPUT", output=outp, output_len=outlen,
         collector_status=reg("ebx"), output_100_hex=safe_dump(outp, 0x100),
         regs=common_regs())
    return False

def h_b04():
    ebp = reg("ebp")
    outp = (ebp + 0x3C) & 0xFFFFFFFF
    emit("B04_ADVAPI_IOCTL_RETURN", ioctl_out=outp,
         ioctl_out_100_hex=safe_dump(outp, 0x100), regs=common_regs())
    return False

def h_b05():
    esp = reg("esp")
    outp = read_u32(esp + 4)
    length = read_u32(esp + 8)
    _state["sys"] = {"outp": outp, "length": length}
    emit("B05_SYSTEMFUNCTION036_ENTRY", sysfunc_out=outp, sysfunc_len=length,
         sys_before_20_hex=safe_dump(outp, 0x20), regs=common_regs())
    return False

def h_b06():
    s = _state["sys"]
    emit("B06_SYSTEMFUNCTION036_RETURN", sysfunc_out=s.get("outp"),
         sysfunc_len=s.get("length"),
         sys_after_20_hex=safe_dump(s.get("outp"), 0x20), regs=common_regs())
    return False

def h_b07():
    esp = reg("esp")
    st = read_u32(esp + 4)
    length = read_u32(esp + 8)
    outp = read_u32(esp + 0xC)
    _state["prga"] = {"state": st, "length": length, "outp": outp}
    emit("B07_ADVAPI_RC4_PRGA_ENTRY", prga_state=st, prga_len=length, prga_out=outp,
         state_before_102_hex=safe_dump(st, 0x102),
         out_before_20_hex=safe_dump(outp, 0x20), regs=common_regs())
    return False

def h_b08():
    p = _state["prga"]
    emit("B08_ADVAPI_RC4_PRGA_RETURN", prga_state=p.get("state"),
         prga_len=p.get("length"), prga_out=p.get("outp"),
         state_after_102_hex=safe_dump(p.get("state"), 0x102),
         out_after_20_hex=safe_dump(p.get("outp"), 0x20), regs=common_regs())
    return False

def h_cpgen():
    emit("CPGEN_ENTRY", regs=common_regs(),
         stack_40_hex=safe_dump(reg("esp"), 0x40))
    return False

def h_b09():
    emit("B09_PROVIDER_RUNTIME_CALL",
         global_31958_hex=safe_dump(0x68031958, 0x20),
         global_3196c_hex=safe_dump(0x6803196C, 0x20),
         global_31980_hex=safe_dump(0x68031980, 0x20),
         regs=common_regs())
    return False

def arm_rsaenh_software_breakpoints():
    if _state["rsaenh_armed"]:
        return
    _state["rsaenh_armed"] = True
    for name, handler in (
        ("CPGEN", h_cpgen),
        ("B09", h_b09),
        ("B11", h_b11),
        ("B12", h_b12),
        ("B13", h_b13),
        ("B14", h_b14),
    ):
        _state["provider_bps"].append(TraceBP(name, ADDR[name], handler))
    emit("RSAENH_SOFTWARE_BREAKPOINTS_ARMED",
         addresses={k: ADDR[k] for k in ("CPGEN","B09","B11","B12","B13","B14")})
    gdb.write("\nCGR640_RSAENH_ARMED\n")

def h_b10():
    arm_rsaenh_software_breakpoints()
    ebp = reg("ebp")
    localp = (ebp - 0x18) & 0xFFFFFFFF
    outp = read_u32(ebp + 0x18)
    outlen = read_u32(ebp + 0x1C)
    cur = read_u32(ebp - 0x48)
    rem = read_u32(ebp - 0x44)
    local20 = read_mem(localp, 0x20)
    xkey = read_mem(0x68031958, 0x20)
    sig = (cur, rem, hx(local20), hx(xkey))
    if sig == _state["last_b10_sig"]:
        return False
    _state["last_b10_sig"] = sig

    if outlen is not None and rem == outlen:
        _state["d640_call_id"] += 1
        _state["accepted_blocks"] = 0

    _state["provider"] = {
        "localp": localp, "outp": outp, "outlen": outlen,
        "cur": cur, "rem": rem, "call_id": _state["d640_call_id"],
    }

    emit("B10_PROVIDER_BEFORE_SYSTEMFUNCTION036",
         d640_call_id=_state["d640_call_id"],
         provider_aux=localp, cgr_out=outp, cgr_len=outlen,
         cgr_cur=cur, cgr_remaining=rem,
         provider_aux_before_20_hex=hx(local20),
         caller_current_20_hex=safe_dump(cur, min(rem or 0, 0x20)),
         xkey_before_hex=hx(xkey),
         regs=common_regs())

    if outlen == 0x280 and rem == 0x280 and outp is not None:
        data = read_mem(outp, 0x280)
        if data is not None:
            path = os.path.join(OUTDIR, "caller-before.bin")
            with open(path, "wb") as f:
                f.write(data)
            emit("TARGET_CGR640_CALLER_BEFORE_SAVED",
                 path=path, caller_before_hex=data.hex())
    return False

def h_b11():
    p = _state["provider"]
    ebp = reg("ebp")
    localp = p.get("localp")
    emit("B11_PROVIDER_AFTER_SYSTEMFUNCTION036",
         d640_call_id=p.get("call_id"),
         provider_aux=localp, cgr_out=p.get("outp"), cgr_len=p.get("outlen"),
         cgr_cur=read_u32(ebp - 0x48), cgr_remaining=read_u32(ebp - 0x44),
         provider_sysfunc_raw20_hex=safe_dump(localp, 0x20),
         regs=common_regs())
    return False

def h_b12():
    esp = reg("esp")
    st = read_u32(esp + 4)
    aux = read_u32(esp + 8)
    outp = read_u32(esp + 0xC)
    length = read_u32(esp + 0x10)
    _state["fips"] = {"state": st, "aux": aux, "outp": outp, "length": length}
    _state["accepted_blocks"] += 1
    emit("B12_PROVIDER_FIPS_ENTRY",
         d640_call_id=_state["provider"].get("call_id"),
         accepted_block_index=_state["accepted_blocks"] - 1,
         provider_state=st, provider_aux_final=aux, provider_out40=outp,
         provider_len=length,
         state_before_20_hex=safe_dump(st, 0x20),
         aux_final_20_hex=safe_dump(aux, 0x20),
         out40_before_hex=safe_dump(outp, 0x28),
         regs=common_regs())
    return False

def h_b13():
    f = _state["fips"]
    emit("B13_PROVIDER_FIPS_RETURN",
         d640_call_id=_state["provider"].get("call_id"),
         provider_state=f.get("state"), provider_aux_final=f.get("aux"),
         provider_out40=f.get("outp"), provider_len=f.get("length"),
         out40_after_hex=safe_dump(f.get("outp"), 0x28),
         state_after_20_hex=safe_dump(f.get("state"), 0x20),
         regs=common_regs())
    return False

def h_b14():
    p = _state["provider"]
    outp = p.get("outp")
    outlen = p.get("outlen")
    final = read_mem(outp, outlen) if outp is not None and outlen else None
    emit("B14_PROVIDER_RUNTIME_RETURN",
         d640_call_id=p.get("call_id"), cgr_out=outp, cgr_len=outlen,
         accepted_blocks=_state["accepted_blocks"],
         output_hex=hx(final),
         global_31958_hex=safe_dump(0x68031958, 0x20),
         global_3196c_hex=safe_dump(0x6803196C, 0x20),
         global_31980_hex=safe_dump(0x68031980, 0x20),
         regs=common_regs())

    if outlen == 0x280 and final is not None:
        path = os.path.join(OUTDIR, "caller-after.bin")
        with open(path, "wb") as f:
            f.write(final)
        emit("TARGET_CGR640_RETURN_CAPTURED", path=path,
             accepted_blocks=_state["accepted_blocks"])
        gdb.write(
            f"\nCGR640_TARGET_RETURN_CAPTURED "
            f"accepted_blocks={_state['accepted_blocks']} events={_seq}\n"
        )
        return True
    return False

mapped = [
    ("B01", h_b01), ("B02", h_b02), ("B03", h_b03),
    ("K00", h_k00),
    ("K01", h_k_source("K01_PROCESS_ID_APPENDED", 0x08)),
    ("K02", h_k_source("K02_THREAD_ID_APPENDED", 0x08)),
    ("K03", h_k_source("K03_TICK_COUNT_APPENDED", 0x10)),
    ("K04", h_k_source("K04_CPU_COUNTERS_RETURN", 0x40)),
    ("K05", h_k_workspace("K05_SYSINFO_05_RAW")),
    ("K06", h_k_source("K06_SYSINFO_03_RETURN", 0x38)),
    ("K07", h_k_source("K07_SYSINFO_07_RETURN", 0x20)),
    ("K08", h_k_source("K08_SYSINFO_02_RETURN", 0x140)),
    ("K09", h_k_source("K09_SYSINFO_21_RETURN", 0x18)),
    ("K10", h_k_source("K10_SYSINFO_2D_RETURN", 0x28)),
    ("K11", h_k_workspace("K11_SYSINFO_08_RAW")),
    ("K12", h_k_workspace("K12_SYSINFO_17_RAW")),
    ("K13", h_k13), ("K14", h_k14), ("K15", h_k15),
    ("K16", h_k16), ("K17", h_k17),
    ("B04", h_b04), ("B05", h_b05), ("B06", h_b06),
    ("B07", h_b07), ("B08", h_b08),
]

_bps = [TraceBP(name, ADDR[name], handler) for name, handler in mapped]
_b10_hw = TraceBP("B10", ADDR["B10"], h_b10, hardware=True)

emit("CAPTURE_ARMED",
     target_cr3=TARGET_CR3,
     low_chain_breakpoints=len(_bps),
     b10_hardware=ADDR["B10"],
     outdir=OUTDIR)

gdb.write(
    "\nCGR640_FULLCHAIN_ARMED "
    f"cr3=0x{TARGET_CR3:08x} low_chain={len(_bps)} out={OUTDIR}\n"
)
gdb.write("DO_NOT_RUN_A_SECOND_PROBE_IN_THIS_JOURNAL\n")
