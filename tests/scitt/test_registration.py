"""Executable handoff probes against the actual offline adapter; constructed only."""
import copy
import hashlib
import json
import socket
from dataclasses import replace
from pathlib import Path

import pytest

cbor2 = pytest.importorskip("cbor2")
scitt_cose = pytest.importorskip("scitt_cose")
from cryptography.hazmat.primitives.asymmetric import ec

from arcs_verify import scitt_registration as v
from .material import (ARTIFACT, ISSUER, SERVICE, ISSUER_KEY, SERVICE_KEY, OTHER_KEY,
                       public, headers, statement, receipt, entry, sidecar, parts,
                       mutate, sign, root, b64)

ACCEPT = {'id': 'constructed-local-policy/v1', 'decision': 'accept'}
DEFAULT = v.Selection(v.SelectedKey(ISSUER, public(ISSUER_KEY), ACCEPT), v.SelectedKey(SERVICE, public(SERVICE_KEY), ACCEPT))
INC = 'registration_receipt_inclusion'
SIG = 'registration_statement_signature'
PROFILE = 'registration_statement_profile'
SUBJECT = 'registration_subject_binding'
TIME = 'registration_time_authenticated'


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError('network use is forbidden in offline verifier tests')
    monkeypatch.setattr(socket, 'socket', deny)
    monkeypatch.setattr(socket, 'create_connection', deny)
    monkeypatch.setattr(socket, 'getaddrinfo', deny)


def run(s=None, p=None, *, target=ARTIFACT, selection=DEFAULT):
    s = statement(target) if s is None else s
    p = receipt(s) if p is None else p
    return v.verify_registration(sidecar([entry(s, p)], target), target=target, selection=selection)['relationships'][0]


def test_constructed_success_and_separate_axes():
    result = run()
    assert result['findings'] == {SUBJECT: 'pass', PROFILE: 'pass', SIG: 'pass', INC: 'pass', TIME: 'not_evaluated', 'statement_issuer_trusted': 'pass', 'transparency_service_trusted': 'pass'}
    assert result['authenticated_service_identity'] == SERVICE
    assert not any(name in result for name in ('registered', 'passed', 'independent_sources'))


@pytest.mark.parametrize('attached', [False, True])
@pytest.mark.parametrize('size,index', [(1, 0), (2, 0), (2, 1), (3, 2), (7, 4), (8, 7), (9, 8), (17, 11)])
def test_independent_recursive_proofs(size, index, attached):
    s = statement()
    leaves = [f'constructed other leaf {i}'.encode() for i in range(size)]
    leaves[index] = s
    p = receipt(s, leaves=leaves, index=index, attached=attached)
    assert run(s, p)['findings'][INC] == 'pass'
    assert run(s + b'\x00', p)['findings'][INC] == 'fail'


def test_B02_pairing_order_and_repeat_do_not_hide_failure():
    s1 = statement()
    h = headers(); h[4] = b'other-opaque-id'
    s2 = statement(header=h)
    p = receipt(s1)
    entries = [entry(s1, p), entry(s2, p), entry(s1, p, registration_time_hint='unauthenticated')]
    outcomes = []
    for ordered in (entries, entries[::-1]):
        report = v.verify_registration(sidecar(ordered), target=ARTIFACT, selection=DEFAULT)
        assert len(report['relationships']) == 2
        results = {r['evaluation_identity']['signed_statement_digest']: r['findings'] for r in report['relationships']}
        assert results[v.digest(s1)][INC] == 'pass'
        assert results[v.digest(s2)][INC] == 'fail'
        assert all(f[SIG] == 'pass' for f in results.values())
        assert sum('SCITT_DUPLICATE_ENTRY' in o['reason_codes'] for o in report['entry_observations']) == 1
        outcomes.append(results)
    assert outcomes[0] == outcomes[1]


def test_B03_exact_duplicate_entries_rejected():
    s = statement(); e = entry(s, receipt(s))
    with pytest.raises(v.InputError, match='uniqueItems'):
        v.verify_registration(sidecar([e, e]), target=ARTIFACT)


def test_B03_context_and_three_digests_prevent_reuse(monkeypatch):
    s = statement(); p = receipt(s)
    baseline = run(s, p)
    variants = [
        run(s, p, target=ARTIFACT + b' '),
        run(statement(header={**headers(), 4: b'different'}), p),
        run(s, mutate(p, 1, {**parts(p)[1], 'unsigned': 'different'})),
        run(s, p, selection=replace(DEFAULT, proof_index=1)),
        run(s, p, selection=replace(DEFAULT, service_key=replace(DEFAULT.service_key, policy=None))),
        run(s, p, selection=replace(DEFAULT, service_key=replace(DEFAULT.service_key, policy={**ACCEPT, 'id': 'different-policy'}))),
        run(s, p, selection=replace(DEFAULT, statement_key=replace(DEFAULT.statement_key, public_key_pem=public(OTHER_KEY)))),
    ]
    monkeypatch.setattr(v, 'VERIFIER', 'constructed-next-verifier-context')
    variants.append(run(s, p))
    assert all(r['evaluation_key'] != baseline['evaluation_key'] for r in variants)
    assert variants[0]['findings'][SUBJECT] == 'fail'
    assert variants[1]['findings'][INC] == 'fail'
    assert variants[-2]['findings'][SIG] == 'fail'
    assert variants[4]['findings']['transparency_service_trusted'] == 'not_evaluated'


def test_B03_missing_target_never_reuses_complete_findings():
    s = statement(); p = receipt(s)
    report = v.verify_registration(sidecar([entry(s, p), entry(s, p, registration_time_hint='hint')]), target=None, selection=DEFAULT)
    assert len(report['relationships']) == 2
    assert all(r['findings'][SUBJECT] == 'not_evaluated' for r in report['relationships'])
    assert all('SCITT_DUPLICATE_ENTRY' not in o['reason_codes'] for o in report['entry_observations'])


def test_B04_service_and_target_hint_disagreement():
    s = statement(); p = receipt(s)
    carrier = sidecar([entry(s, p, transparency_service={'service_id': 'wrong'})])
    carrier['srs_receipt'].update(receipt_id='wrong', byte_size=1, exact_artifact_digest=v.digest(b'wrong'))
    report = v.verify_registration(carrier, target=ARTIFACT, selection=DEFAULT)
    assert report['relationships'][0]['authenticated_service_identity'] == SERVICE
    assert report['relationships'][0]['findings'][INC] == 'pass'
    assert set(report['entry_observations'][0]['reason_codes']) == {'SCITT_SERVICE_HINT_DISAGREEMENT', 'SCITT_TARGET_HINT_DISAGREEMENT', 'SCITT_TARGET_SIZE_HINT_DISAGREEMENT', 'SCITT_RECEIPT_ID_HINT_DISAGREEMENT'}


@pytest.mark.parametrize('invalid_b', [False, True])
def test_B05_B06_T17_service_outcomes_remain_separate(invalid_b):
    s = statement(); pa = receipt(s); pb = receipt(s, key=OTHER_KEY)
    if invalid_b:
        pb = mutate(pb, 3, b'bad signature')
    selection_b = replace(DEFAULT, service_key=v.SelectedKey('service:B', public(OTHER_KEY), {**ACCEPT, 'decision': 'reject'}))
    for rev in (False, True):
        entries = [entry(s, pa), entry(s, pb)]
        if rev: entries.reverse()
        report = v.verify_registration(sidecar(entries), target=ARTIFACT, selection=DEFAULT, entry_selections={0 if rev else 1: selection_b})
        findings = {r['context']['trust_policy']['transparency_service']['identity']: r['findings'] for r in report['relationships']}
        assert findings[SERVICE][INC] == 'pass'
        assert findings['service:B'][INC] == ('fail' if invalid_b else 'pass')
        assert findings[SERVICE]['transparency_service_trusted'] == 'pass'
        assert findings['service:B']['transparency_service_trusted'] == 'fail'


@pytest.mark.parametrize('value', [123, 999999, 'untrusted-time'])
def test_B07_B19_T12_unsigned_time_is_an_observation(value):
    s = statement(); p = receipt(s, unprotected={15: {6: value}})
    result = run(s, p)
    assert result['findings'][INC] == 'pass'
    assert result['findings'][TIME] == 'not_evaluated'
    assert result['registration_time_reported']['provenance'] == 'unauthenticated'
    assert result['registration_time_reported']['value'] == value
    report = v.verify_registration(sidecar([entry(s, p, registration_time_hint='earlier')]), target=ARTIFACT, selection=DEFAULT)
    assert report['entry_observations'][0]['registration_time_reported']['provenance'] == 'unauthenticated'


@pytest.mark.parametrize('case', ['B01', 'B08', 'B09', 'B10', 'B11-258', 'B11-259', 'B11-260', 'B13', 'B14', 'B18'])
def test_profile_cases(case):
    h = headers(); unsigned = {}; detached = False
    if case == 'B01': unsigned['receipt'] = b'some receipt'
    if case == 'B08': h['extra'] = ARTIFACT
    if case == 'B09': h[3] = 'application/json'
    if case == 'B10': unsigned[3] = 'application/json'
    if case.startswith('B11'):
        label = int(case.split('-')[1]); unsigned[label] = h.pop(label, 'locator')
    if case == 'B13': h[2] = [1]
    if case == 'B14': h[15][6] = 123
    if case == 'B18': detached = True
    s = statement(header=h, unprotected=unsigned, detached=detached)
    r = run(s)
    assert r['findings'][PROFILE] == 'fail'
    assert r['findings'][INC] == 'pass'  # Correct inclusion does not repair the profile.
    if case != 'B18': assert r['findings'][SIG] == 'pass'


@pytest.mark.parametrize('location', ['protected', 'claims', 'unprotected', 'trailing'])
def test_B12_T08_duplicate_or_malformed_statement(location):
    s = statement()
    if location == 'protected': s = mutate(s, 0, b'\xa2\x01\x27\x01\x27')
    elif location == 'claims': s = mutate(s, 0, b'\xa1\x0f\xa2\x01\x61a\x01\x61b')
    elif location == 'unprotected':
        # Tag18,array4, exact protected bytes, duplicate map, payload,signature.
        p = parts(s); s = b'\xd2\x84' + cbor2.dumps(p[0]) + b'\xa2\x04\x41a\x04\x41b' + cbor2.dumps(p[2]) + cbor2.dumps(p[3])
    else: s += b'\x00'
    r = run(s)
    assert all(r['findings'][axis] == 'fail' for axis in (PROFILE, SUBJECT, SIG, INC))


@pytest.mark.parametrize('case', ['B15', 'B16', 'T09'])
def test_invalid_carrier_precedes_all_content_reading(case, monkeypatch):
    s = statement(); e = entry(s, receipt(s))
    if case == 'B15': e['receipt']['digest'] = v.digest(b'wrong')
    if case == 'B16': e['signed_statement']['bytes'] = '**invalid**'
    if case == 'T09': del e['signed_statement']
    def forbidden(*a, **kw): raise AssertionError('parsed despite R02')
    monkeypatch.setattr(v, '_evaluate', forbidden)
    r = v.verify_registration(sidecar([e]), target=ARTIFACT, selection=DEFAULT)['relationships'][0]
    assert set(r['findings'].values()) == {'not_evaluated'}
    assert r['reason_codes'] == ['SCITT_CARRIER_BYTES_INVALID']


def test_B17_receipt_id_is_not_digest_subject():
    h = headers(); h[15][2] = 'constructed:receipt:1'
    r = run(statement(header=h))
    assert r['findings'][SUBJECT] == 'fail'
    assert r['findings'][SIG] == r['findings'][INC] == 'pass'


def test_T02_T18_exact_bytes_and_occurrence():
    s = statement(); p = receipt(s)
    for changed in (ARTIFACT + b'\n', ARTIFACT.replace(b'receipt:1', b'receipt:2')):
        r = run(s, p, target=changed)
        assert r['findings'][SUBJECT] == 'fail'
        assert r['findings'][INC] == r['findings'][SIG] == 'pass'


@pytest.mark.parametrize('body', [b'', b'HTTP 201 Created', b'\xff', cbor2.dumps([1, 2])])
def test_T06_arbitrary_response_is_not_inclusion(body):
    s = statement(); r = run(s, body)
    assert r['findings'][INC] != 'pass'


def test_T07_T11_native_attached_wrong_root_requires_adapter_guard():
    s1 = statement(); s2 = statement(header={**headers(), 4: b'other-id'})
    p = receipt(s1, attached=True)
    # Qualifies an exact pinned-backend limitation, not an assertion of native
    # conformance. The adapter must close this independently reproduced gap.
    native = scitt_cose.verify_receipt(p, leaf_entry_hex=s2.hex(), log_public_key_pem=public(SERVICE_KEY))
    assert native.ok and bytes.fromhex(native.root) != root([s1])
    assert run(s1, p)['findings'][INC] == 'pass'
    assert run(s2, p)['findings'][INC] == 'fail'
    assert run(s1, receipt(s1, attached=True, signed_root=b'x' * 32))['findings'][INC] == 'fail'


@pytest.mark.parametrize('kind', ['unknown', 'wrong-issuer', 'wrong-key', 'no-policy', 'untrusted', 'swapped-roles'])
def test_T10_explicit_keys_do_not_establish_trust(kind):
    selected = DEFAULT
    if kind == 'unknown': selected = v.Selection()
    if kind == 'wrong-issuer': selected = replace(DEFAULT, statement_key=replace(DEFAULT.statement_key, identity='wrong'))
    if kind == 'wrong-key': selected = replace(DEFAULT, statement_key=replace(DEFAULT.statement_key, public_key_pem=public(OTHER_KEY)))
    if kind == 'no-policy': selected = v.Selection(replace(DEFAULT.statement_key, policy=None), replace(DEFAULT.service_key, policy=None))
    if kind == 'untrusted': selected = replace(DEFAULT, service_key=replace(DEFAULT.service_key, policy={**ACCEPT, 'decision': 'reject'}))
    if kind == 'swapped-roles': selected = v.Selection(DEFAULT.service_key, DEFAULT.statement_key)
    f = run(selection=selected)['findings']
    if kind in ('unknown', 'wrong-issuer', 'swapped-roles'): assert f[SIG] == 'not_evaluated'
    if kind == 'unknown': assert f[INC] == 'not_evaluated'
    if kind == 'wrong-key': assert f[SIG] == 'fail'
    if kind == 'no-policy':
        assert f[SIG] == f[INC] == 'pass'
        assert f['statement_issuer_trusted'] == f['transparency_service_trusted'] == 'not_evaluated'
    if kind == 'untrusted': assert f[INC] == 'pass' and f['transparency_service_trusted'] == 'fail'
    if kind == 'swapped-roles': assert f[INC] == 'fail'


def test_T13_signed_iat_does_not_supply_time_policy_or_authenticate_earlier_issuance():
    s = statement(); p = receipt(s, header={1: -8, 395: 1, 15: {6: 1900000000}})
    r = run(s, p)
    assert r['findings'][INC] == 'pass'
    assert r['findings'][TIME] == 'not_evaluated'


def test_T19_original_submission_is_not_replaced_with_augmented_statement():
    s = statement(); p = receipt(s)
    augmented = mutate(s, 1, {396: p})
    original = run(s, p); changed = run(augmented, p)
    assert original['findings'][PROFILE] == original['findings'][INC] == 'pass'
    assert changed['findings'][PROFILE] == changed['findings'][INC] == 'fail'
    assert changed['findings'][SIG] == 'pass'


@pytest.mark.parametrize('badproof', [[0, 0, []], [1, True, []], [2, 0, []], [2, 0, [b'short']], [2**64, 0, []], [1, 0, [b'x' * 32]], {1: 2}])
def test_malformed_proofs_fail_even_without_service_key(badproof):
    s = statement(); p = mutate(receipt(s), 1, {396: {-1: [cbor2.dumps(badproof)]}})
    assert run(s, p, selection=v.Selection())['findings'][INC] == 'fail'


def test_selected_proof_and_malformed_unselected_proof():
    s = statement(); p = receipt(s, leaves=[s, b'other'], index=0)
    unsigned = parts(p)[1]; correct = unsigned[396][-1][0]
    wrong = cbor2.dumps([2, 1, [root([b'other'])]])
    unsigned[396][-1] = [wrong, correct]
    multiple = mutate(p, 1, unsigned)
    assert run(s, multiple)['findings'][INC] == 'fail'
    assert run(s, multiple, selection=replace(DEFAULT, proof_index=1))['findings'][INC] == 'pass'
    unsigned[396][-1] = [correct, cbor2.dumps([0, 0, []])]
    assert run(s, mutate(p, 1, unsigned))['findings'][INC] == 'fail'


@pytest.mark.parametrize('vds', [2, 999])
def test_unsupported_proof_scheme_is_not_evaluated(vds):
    s = statement(); r = run(s, receipt(s, header={1: -8, 395: vds}))
    assert r['findings'][INC] == 'not_evaluated'
    assert 'SCITT_PROOF_PROFILE_UNSUPPORTED' in r['reason_codes']


def test_unknown_critical_receipt_header_fails():
    s = statement(); p = receipt(s, header={1: -8, 395: 1, 2: [999], 999: True})
    assert run(s, p)['findings'][INC] == 'fail'


@pytest.mark.parametrize('alg,curve', [(-7, ec.SECP256R1()), (-35, ec.SECP384R1())])
def test_independent_ec_signatures(alg, curve):
    key = ec.derive_private_key(100, curve)
    h = {**headers(), 1: alg}; s = statement(header=h, key=key)
    p = receipt(s, header={1: alg, 395: 1}, key=key)
    selected = v.Selection(v.SelectedKey(ISSUER, public(key)), v.SelectedKey(SERVICE, public(key)))
    r = run(s, p, selection=selected)
    assert r['findings'][SIG] == r['findings'][INC] == 'pass'
    assert r['findings']['statement_issuer_trusted'] == 'not_evaluated'


def test_nonminimal_encoding_discloses_backend_limitation():
    s = statement()
    # Valid CBOR array4 encoded non-minimally; bytes are the selected leaf.
    s = b'\xd2\x98\x04' + s[2:]
    r = run(s)
    assert r['findings'][PROFILE] == 'pass'
    assert r['findings'][SIG] == 'not_evaluated'
    assert r['findings'][INC] == 'pass'
    assert 'SCITT_STATEMENT_ENCODING_UNSUPPORTED_BY_BACKEND' in r['reason_codes']


def test_T05_absent_registration():
    report = v.verify_registration(None, target=ARTIFACT)
    assert set(report['relationships'][0]['findings'].values()) == {'not_evaluated'}


def test_cli_selection_and_unchanged_srs_dispatch(tmp_path, capsys, monkeypatch):
    from arcs_verify import cli
    s = statement(); carrier = sidecar([entry(s, receipt(s))])
    (tmp_path / 'sidecar.json').write_text(json.dumps(carrier))
    (tmp_path / 'artifact.json').write_bytes(ARTIFACT)
    selection = {'format': 'arcs-verify.scitt-local-selection/experimental-1', 'default': {
        'statement_issuer': {'identity': ISSUER, 'public_key_pem': public(ISSUER_KEY).decode(), 'policy': ACCEPT},
        'transparency_service': {'identity': SERVICE, 'public_key_pem': public(SERVICE_KEY).decode()}}}
    path = tmp_path / 'selection.json'; path.write_text(json.dumps(selection))
    assert cli.main(['scitt-registration', str(tmp_path / 'sidecar.json'), '--artifact', str(tmp_path / 'artifact.json'), '--selection', str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output['relationships'][0]['findings']['transparency_service_trusted'] == 'not_evaluated'
    assert output['relationships'][0]['findings'][INC] == 'pass'
    def legacy(args): return 73
    monkeypatch.setattr(cli, '_verify_srs', legacy)
    assert cli.main(['legacy-receipt.json']) == 73
    path.write_text('{"format":"x","format":"y"}')
    assert cli.main(['scitt-registration', str(tmp_path / 'sidecar.json'), '--selection', str(path)]) == 2


@pytest.mark.parametrize('bad', [None, True, {'decision': 'accept'}, {'id': 'x', 'decision': True}, {'id': '', 'decision': 'accept'}])
def test_invalid_policy_never_becomes_implicit_trust(bad):
    selected = replace(DEFAULT, service_key=replace(DEFAULT.service_key, policy=bad))
    if bad is None:
        assert run(selection=selected)['findings']['transparency_service_trusted'] == 'not_evaluated'
    else:
        with pytest.raises(v.InputError): run(selection=selected)


def test_malformed_statement_crit_does_not_crash():
    h = headers(); h[2] = [[1]]
    r = run(statement(header=h))
    assert r['findings'][PROFILE] == r['findings'][SIG] == 'fail'
    assert r['findings'][INC] == 'pass'


def test_T03_T04_T05_srs_validity_remains_independent():
    from arcs_verify.verifier import verify_receipt
    from arcs_verify import verifier
    base = Path(verifier.__file__).parent
    golden = base / 'contracts/dagr-srs-verification-report-v0-1/golden'
    keyring = json.loads((golden / 'trust-bundle.json').read_bytes())
    schema = base / 'data/srs-envelope-v0.2.1.schema.json'
    admission = (golden / 'admission-receipt.json').read_bytes()
    outcome = (golden / 'outcome-receipt.json').read_bytes()
    original_report = verify_receipt(json.loads(admission), keyring, schema_path=schema)
    other_report = verify_receipt(json.loads(outcome), keyring, schema_path=schema)
    assert original_report.passed and other_report.passed
    # T03: another valid SRS receipt cannot satisfy an exact-artifact binding.
    s = statement(admission)
    result = run(s, receipt(s), target=outcome)
    assert result['findings'][SUBJECT] == 'fail' and result['findings'][INC] == 'pass'
    # T04: actual SRS verification fails but exact constructed registration passes.
    invalid = json.loads(admission); invalid['receipt_signature']['signature'] = 'A' * 86
    invalid_bytes = json.dumps(invalid).encode()
    assert not verify_receipt(invalid, keyring, schema_path=schema).passed
    result = run(target=invalid_bytes)
    assert result['findings'][SUBJECT] == result['findings'][SIG] == result['findings'][INC] == 'pass'
    # T05: calling the opt-in absent-registration API neither mutates nor gates SRS.
    assert set(v.verify_registration(None, target=admission)['relationships'][0]['findings'].values()) == {'not_evaluated'}
    assert verify_receipt(json.loads(admission), keyring, schema_path=schema) == original_report


def test_B03_same_relation_with_different_per_entry_policy_not_reused():
    s = statement(); p = receipt(s)
    reject = replace(DEFAULT, service_key=replace(DEFAULT.service_key, policy={**ACCEPT, 'decision': 'reject'}))
    report = v.verify_registration(sidecar([entry(s, p), entry(s, p, registration_time_hint='hint')]), target=ARTIFACT,
                                   selection=DEFAULT, entry_selections={1: reject})
    assert len(report['relationships']) == 2
    assert {r['findings']['transparency_service_trusted'] for r in report['relationships']} == {'pass', 'fail'}
    assert all('SCITT_DUPLICATE_ENTRY' not in o['reason_codes'] for o in report['entry_observations'])


def test_duplicate_receipt_map_and_trailing_proof_bytes():
    s = statement(); p = receipt(s)
    bad = mutate(p, 0, b'\xa3\x01\x27\x01\x27\x19\x01\x8b\x01')
    assert run(s, bad)['findings'][INC] == 'fail'
    unsigned = parts(p)[1]; unsigned[396][-1][0] += b'\x00'
    assert run(s, mutate(p, 1, unsigned))['findings'][INC] == 'fail'


def test_multiple_bad_carriers_retained_and_valid_relationship_still_evaluated():
    s = statement(); p = receipt(s); e = entry(s, p)
    a = copy.deepcopy(e); a['receipt']['digest'] = v.digest(b'a')
    b = copy.deepcopy(e); b['receipt']['digest'] = v.digest(b'b')
    report = v.verify_registration(sidecar([a, b, e]), target=ARTIFACT, selection=DEFAULT)
    assert len(report['relationships']) == 3
    assert sum(r['findings'][INC] == 'pass' for r in report['relationships']) == 1
    assert sum(r['reason_codes'] == ['SCITT_CARRIER_BYTES_INVALID'] for r in report['relationships']) == 2


def test_certificate_reference_profile_remains_unsupported():
    h = headers(); h[33] = b'certificate requires separate profile validation'
    r = run(statement(header=h))
    assert r['findings'][PROFILE] == 'not_evaluated'
    assert r['findings'][INC] == r['findings'][SIG] == 'pass'


def test_cli_failure_findings_are_not_process_success_claims(tmp_path, capsys):
    s = statement(); p = receipt(s)
    carrier = sidecar([entry(s, mutate(p, 3, b'wrong'))])
    f = tmp_path / 'carrier.json'; f.write_text(json.dumps(carrier))
    # No service key: no cryptographic trust defaults, report production only.
    assert v.main([str(f)]) == 0
    assert json.loads(capsys.readouterr().out)['relationships'][0]['findings'][INC] == 'not_evaluated'


def test_source_pins_detect_contract_and_backend_drift(tmp_path, monkeypatch):
    pin, _ = v._contracts()
    import shutil
    shutil.copytree(v.CONTRACT, tmp_path / 'contracts')
    (tmp_path / 'contracts/binding-rules.json').write_text('{}')
    monkeypatch.setattr(v, 'CONTRACT', tmp_path / 'contracts')
    with pytest.raises(v.InputError, match='contract source digest'):
        v._contracts()
    pin['backend']['files']['receipt.py'] = '0' * 64
    with pytest.raises(v.InputError, match='backend source digest'):
        v._backend(pin)


def test_private_key_is_not_a_public_selection():
    from cryptography.hazmat.primitives import serialization
    private = ISSUER_KEY.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    with pytest.raises(v.InputError, match='public PEM'):
        v.SelectedKey(ISSUER, private).context()


def test_T08_tampered_statement_signature_and_protected_header():
    s = statement(); p = receipt(s)
    bad_signature = mutate(s, 3, b'x' * 64)
    h = headers(); h[4] = b'changed-without-resigning'
    bad_header = mutate(s, 0, cbor2.dumps(h))
    for changed in (bad_signature, bad_header):
        r = run(changed, p)
        assert r['findings'][SIG] == r['findings'][INC] == 'fail'


def test_retained_constructed_replay_inputs_and_outputs():
    fixtures = Path(__file__).resolve().parents[2] / 'docs/scitt-offline/constructed'
    for line in (fixtures / 'SHA256SUMS').read_text().splitlines():
        expected, name = line.split('  ', 1)
        assert hashlib.sha256((fixtures / name).read_bytes()).hexdigest() == expected
    selected, entries = v.read_selection(fixtures / 'selection.json')
    for order in ('forward', 'reverse'):
        result = v.verify_registration(json.loads((fixtures / f'{order}-sidecar.json').read_bytes()),
                                       target=(fixtures / 'artifact.json').read_bytes(), selection=selected, entry_selections=entries)
        assert result == json.loads((fixtures / f'{order}-report.json').read_bytes())
