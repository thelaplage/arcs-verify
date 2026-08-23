from dataclasses import dataclass
from hashlib import sha256
import json

REQUIRED=("offer","discovery","selection","quote","quote_acceptance","authorization","execution","receipt","witness","verification","sla","settlement","history")

@dataclass(frozen=True)
class MarketAuditPacket:
    packet_id:str
    artifact_refs:dict[str,str]
    created_at:str
    authority_effect:str="none"
    truth_effect:str="none"
    admission_effect:str="none"

    def __post_init__(self):
        if any(getattr(self,k)!="none" for k in ("authority_effect","truth_effect","admission_effect")): raise ValueError("audit packet cannot promote semantics")

    def digest(self)->str:
        body={"packet_id":self.packet_id,"artifact_refs":dict(sorted(self.artifact_refs.items())),"created_at":self.created_at,"authority_effect":"none","truth_effect":"none","admission_effect":"none"}
        return sha256(json.dumps(body,sort_keys=True,separators=(",",":")).encode()).hexdigest()

def audit_completeness(packet:MarketAuditPacket)->dict:
    missing=[k for k in REQUIRED if k not in packet.artifact_refs]
    return {"complete":not missing,"missing":missing,"packet_digest":packet.digest(),"authority_effect":"none"}
