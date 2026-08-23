from __future__ import annotations
import hashlib,json
from dataclasses import dataclass
from typing import Mapping,Sequence

SCHEMA="arcs.verify.federation-replay.v0.1"
PASS="PASS"; FAIL="FAIL"; NOT_EVALUATED="NOT_EVALUATED"

def sha256_bytes(b:bytes)->str: return "sha256:"+hashlib.sha256(b).hexdigest()

@dataclass(frozen=True,slots=True)
class ReplayCheck:
 ref:str; kind:str; status:str; reason:str=""

@dataclass(frozen=True,slots=True)
class FederationReplayReport:
 run_id:str; checks:tuple[ReplayCheck,...]; overall_status:str; authority_effect:str="none"; schema_version:str=SCHEMA

def replay_federation_run(envelope:Mapping[str,object], artifact_bytes:Mapping[str,bytes])->FederationReplayReport:
 run_id=str(envelope.get("run_id", ""))
 rows=envelope.get("artifacts", [])
 if not run_id or not isinstance(rows,Sequence): raise ValueError("invalid federation run envelope")
 checks=[]
 for row in rows:
  if not isinstance(row,Mapping):
   checks.append(ReplayCheck("","unknown",FAIL,"invalid artifact row")); continue
  ref=str(row.get("ref","")); kind=str(row.get("kind","")); expected=str(row.get("digest",""))
  if ref not in artifact_bytes:
   checks.append(ReplayCheck(ref,kind,NOT_EVALUATED,"artifact bytes unavailable")); continue
  actual=sha256_bytes(artifact_bytes[ref])
  checks.append(ReplayCheck(ref,kind,PASS if actual==expected else FAIL,"" if actual==expected else "digest mismatch"))
 overall=FAIL if any(c.status==FAIL for c in checks) else (NOT_EVALUATED if any(c.status==NOT_EVALUATED for c in checks) else PASS)
 return FederationReplayReport(run_id,tuple(checks),overall)
