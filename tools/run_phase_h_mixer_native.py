#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, platform, subprocess, sys
from pathlib import Path

SCHEMA="cgr640-h-mixer-reduced-v2"
def sha(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
def dec(v,n,name):
    if not isinstance(v,str):raise ValueError(f"{name}: missing")
    b=bytes.fromhex(v)
    if len(b)!=n:raise ValueError(f"{name}: expected {n}, got {len(b)}")
    return b
def hidden(profile,k):
    if profile=="OLD":return k,0
    if profile=="WS":return 0,k
    if profile=="SPLIT":return (k+1)//2,k//2
    raise ValueError("bad profile")
def knownmask(n,bits):
    u=((1<<bits)-1 if bits else 0).to_bytes(n,"big")
    return bytes((~x)&255 for x in u)
def load(path:Path):
    d=json.loads(path.read_text())
    if d.get("schema")!=SCHEMA or d.get("isolation")!="single-reduced-instance":raise ValueError("bad schema/isolation")
    xs=d.get("instances");
    if not isinstance(xs,list) or len(xs)!=1:raise ValueError("challenge must contain one instance")
    i=xs[0]; profile=i.get("profile"); k=i.get("k"); used=i.get("used")
    if profile not in ("OLD","WS","SPLIT") or not isinstance(k,int) or not 1<=k<=32 or used!=600:raise ValueError("bad profile/k/used")
    ob,wb=hidden(profile,k)
    if (i.get("unknown_bits_old_state"),i.get("unknown_bits_workspace"),i.get("unknown_bits_total"))!=(ob,wb,k):raise ValueError("hidden-bit metadata mismatch")
    om=dec(i.get("old_state_known_mask_hex"),80,"old mask"); wm=dec(i.get("workspace_known_mask_hex"),used,"ws mask")
    ov=dec(i.get("old_state_known_value_hex"),80,"old value"); wv=dec(i.get("workspace_known_value_hex"),used,"ws value"); t=dec(i.get("target_new_state_hex"),80,"target")
    if om!=knownmask(80,ob) or wm!=knownmask(used,wb):raise ValueError("mask does not match campaign semantics")
    if any(v&(~m&255) for v,m in zip(ov,om)) or any(v&(~m&255) for v,m in zip(wv,wm)):raise ValueError("known value sets hidden bits")
    if hashlib.sha256(t).hexdigest()!=i.get("target_new_state_sha256"):raise ValueError("target hash mismatch")
    return i
def kv(s):
    r={}
    for line in s.splitlines():
        if "=" in line:
            a,b=line.split("=",1);r[a.strip()]=b.strip()
    return r

def main():
    root=Path(__file__).resolve().parents[1]
    ap=argparse.ArgumentParser();ap.add_argument("challenge",type=Path);ap.add_argument("--mode",choices=("search","bench"),default="search");ap.add_argument("--start",type=int,default=0);ap.add_argument("--count",type=int,default=0);ap.add_argument("--build",action="store_true");ap.add_argument("--cc",default="cc");ap.add_argument("--source",type=Path,default=root/"tools/solve_phase_h_mixer_native.c");ap.add_argument("--binary",type=Path,default=root/"tools/solve_phase_h_mixer_native");ap.add_argument("--verifier",type=Path,default=root/"tools/verify_phase_h_mixer_reduced_candidate.py");ap.add_argument("--json-out",type=Path,default=None);args=ap.parse_args()
    ch=args.challenge.resolve();src=args.source.resolve();binp=args.binary.resolve();ver=args.verifier.resolve();inst=load(ch)
    if args.build:
        cmd=[args.cc,"-O3","-std=c11","-Wall","-Wextra",str(src),"-o",str(binp)];print("BUILD_COMMAND="+" ".join(cmd));subprocess.run(cmd,check=True)
    if not binp.is_file():raise SystemExit("FAIL native binary missing; use --build")
    cmd=[str(binp),inst["profile"],str(inst["k"]),str(inst["used"]),inst["old_state_known_value_hex"],inst["workspace_known_value_hex"],inst["target_new_state_hex"],str(args.start),str(args.count),args.mode]
    p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);print(p.stdout,end="")
    if p.returncode:return p.returncode
    r=kv(p.stdout);verified=None
    if "FIRST_MATCH_COUNTER" in r:
        q=subprocess.run([sys.executable,str(ver),inst["id"],r["CANDIDATE_OLD_STATE_HEX"],r["CANDIDATE_WORKSPACE_PREFIX_HEX"],"--challenge",str(ch)],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True);print("--- INDEPENDENT_VERIFIER ---");print(q.stdout,end="");verified=(q.returncode==0);print("INDEPENDENT_VERIFIER="+("PASS" if verified else "FAIL"));
        if not verified:return 1
    if args.mode=="search" and r.get("STATUS")=="FOUND" and verified is not True:raise SystemExit("FAIL FOUND without verifier PASS")
    result={"campaign":"MIX-CPU","instance_id":inst["id"],"profile":inst["profile"],"unknown_bits":inst["k"],"mode":args.mode,"challenge_sha256":sha(ch),"solver_source_sha256":sha(src),"solver_binary_sha256":sha(binp),"verifier_sha256":sha(ver),"status":r.get("STATUS"),"tested_candidates":int(r["TESTED"]),"matches":int(r["MATCHES"]),"wall_seconds":float(r["ELAPSED_SECONDS"]),"throughput_candidates_per_second":float(r["THROUGHPUT_CANDIDATES_PER_SECOND"]),"counter":int(r["FIRST_MATCH_COUNTER"]) if "FIRST_MATCH_COUNTER" in r else None,"candidate_verified":verified,"host":platform.node(),"machine":platform.machine(),"python":platform.python_version()}
    if args.json_out:
        out=args.json_out.resolve();out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n");print(f"RESULT_JSON={out}\nRESULT_JSON_SHA256={sha(out)}")
    print("PHASE_H_MIXER_CPU_RUN=PASS");return 0
if __name__=="__main__":raise SystemExit(main())
