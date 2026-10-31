#!/usr/bin/env python3
import argparse, ast, configparser, json
from pathlib import Path

SPECIAL = {"GLOBAL", "REPORTS", "LOGGER", "ALIASES"}
MODE_MAP = {"MASTER":"homebrew_server","SERVER":"homebrew_server","PEER":"homebrew_outbound","CLIENT":"homebrew_outbound","OUTBOUND":"homebrew_outbound","OPENBRIDGE":"openbridge"}

def parse_cfg(path: Path):
    cp=configparser.ConfigParser(interpolation=None, strict=False)
    cp.optionxform=str.upper
    cp.read(path)
    systems=[]
    for section in cp.sections():
        if section.upper() in SPECIAL: continue
        mode=cp[section].get("MODE","").upper()
        if not mode: continue
        systems.append({
            "name":section,"legacy_mode":mode,"normalized_mode":MODE_MAP.get(mode,"unknown"),
            "enabled":cp[section].getboolean("ENABLED",fallback=True),
            "ip":cp[section].get("IP",fallback=None),"port":cp[section].getint("PORT",fallback=None),
            "target_ip":cp[section].get("TARGET_IP",fallback=cp[section].get("MASTER_IP",fallback=cp[section].get("SERVER_IP",fallback=None))),
            "target_port":cp[section].getint("TARGET_PORT",fallback=cp[section].getint("MASTER_PORT",fallback=cp[section].getint("SERVER_PORT",fallback=None))),
            "max_repeaters":cp[section].getint("MAX_REPEATERS",fallback=cp[section].getint("MAX_PEERS",fallback=None)),
        })
    return systems

def literal_assignments(path: Path):
    tree=ast.parse(path.read_text())
    vals={}
    for node in tree.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in {"BRIDGES","OBP_BRIDGES","UNIT"}:
            vals[node.targets[0].id]=ast.literal_eval(node.value)
    return vals

def parse_rules(path: Path):
    vals=literal_assignments(path)
    bridges=[]
    for name,members in vals.get("BRIDGES",{}).items():
        out=[]
        for m in members:
            out.append({
                "system":m["SYSTEM"],"timeslot":m["TS"],"talkgroup":m["TGID"],"active":bool(m["ACTIVE"]),
                "timeout_minutes":m.get("TIMEOUT",0),"timeout_type":m.get("TO_TYPE","NONE"),
                "on":m.get("ON",[]),"off":m.get("OFF",[]),"reset":m.get("RESET",[]),
            })
        bridges.append({"name":name,"members":out})
    return {"bridges":bridges,"obp_bridges":vals.get("OBP_BRIDGES",{}),"unit_systems":vals.get("UNIT",[])}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--config",required=True); ap.add_argument("--rules",required=True); ap.add_argument("--out",required=True); a=ap.parse_args()
    systems=parse_cfg(Path(a.config)); rules=parse_rules(Path(a.rules))
    names={s["name"] for s in systems}; missing=sorted({m["system"] for b in rules["bridges"] for m in b["members"] if m["system"] not in names})
    result={"systems":systems,**rules,"validation":{"missing_system_references":missing}}
    Path(a.out).write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({"systems":len(systems),"bridges":len(rules["bridges"]),"bridge_members":sum(len(b["members"]) for b in rules["bridges"]),"missing_system_references":missing},indent=2))
if __name__=="__main__": main()
