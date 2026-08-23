from federation_replay import FAIL,NOT_EVALUATED,PASS,replay_federation_run,sha256_bytes

def test_replay_pass_fail_and_not_evaluated():
 good=b"good"; bad=b"bad"
 env={"run_id":"run:1","artifacts":[{"kind":"srs","ref":"a","digest":sha256_bytes(good)},{"kind":"registry","ref":"b","digest":sha256_bytes(bad)},{"kind":"memory","ref":"c","digest":"sha256:"+"0"*64}]}
 r=replay_federation_run(env,{"a":good,"b":b"tampered"})
 assert [c.status for c in r.checks]==[PASS,FAIL,NOT_EVALUATED]
 assert r.overall_status==FAIL
 assert r.authority_effect=="none"

def test_missing_only_is_not_evaluated_not_failure():
 r=replay_federation_run({"run_id":"run:2","artifacts":[{"kind":"x","ref":"x","digest":"sha256:"+"0"*64}]},{})
 assert r.overall_status==NOT_EVALUATED
