from market_audit_packet import MarketAuditPacket, audit_completeness

def test_incomplete_packet_stays_non_authoritative():
    p=MarketAuditPacket('p1',{'offer':'o','authorization':'a'},'2026-08-23T00:00:00Z')
    r=audit_completeness(p)
    assert r['complete'] is False
    assert r['authority_effect'] == 'none'
