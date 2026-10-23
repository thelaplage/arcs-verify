"""Reproduce constructed offline examples; never registers with any service.

Run from an installed/scitt-enabled environment against this source checkout.
Output is deliberately separate from the SRS reserved real-registration fixture.
"""
import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tests'))
from scitt.material import (ARTIFACT, ISSUER, SERVICE, ISSUER_KEY, SERVICE_KEY,
                            public, statement, headers, receipt, sidecar, entry)
from arcs_verify.scitt_registration import read_selection, verify_registration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    policy = {'id': 'constructed-local-policy/v1', 'decision': 'accept'}
    selected = {'format': 'arcs-verify.scitt-local-selection/experimental-1', 'default': {
        'statement_issuer': {'identity': ISSUER, 'public_key_pem': public(ISSUER_KEY).decode(), 'policy': policy},
        'transparency_service': {'identity': SERVICE, 'public_key_pem': public(SERVICE_KEY).decode(), 'policy': policy}}}
    (args.output / 'artifact.json').write_bytes(ARTIFACT)
    (args.output / 'selection.json').write_text(json.dumps(selected, indent=2) + '\n')
    s1 = statement(); s2 = statement(header={**headers(), 4: b'other-opaque-id'})
    p = receipt(s1)
    for name, data in [('statement-s1.cose', s1), ('statement-s2.cose', s2), ('receipt-p.cose', p)]:
        (args.output / name).write_bytes(data)
    selection, per_entry = read_selection(args.output / 'selection.json')
    for name, entries in [('forward', [entry(s1, p), entry(s2, p)]), ('reverse', [entry(s2, p), entry(s1, p)])]:
        carrier = sidecar(entries)
        report = verify_registration(carrier, target=ARTIFACT, selection=selection, entry_selections=per_entry)
        for suffix, value in [('sidecar', carrier), ('report', report)]:
            (args.output / f'{name}-{suffix}.json').write_text(json.dumps(value, indent=2) + '\n')
        got = {r['evaluation_identity']['signed_statement_digest']: r['findings']['registration_receipt_inclusion'] for r in report['relationships']}
        assert got == {'sha256:' + hashlib.sha256(s1).hexdigest(): 'pass', 'sha256:' + hashlib.sha256(s2).hexdigest(): 'fail'}
    names = ['artifact.json', 'selection.json', 'statement-s1.cose', 'statement-s2.cose', 'receipt-p.cose',
             'forward-sidecar.json', 'forward-report.json', 'reverse-sidecar.json', 'reverse-report.json']
    (args.output / 'SHA256SUMS').write_text(''.join(hashlib.sha256((args.output / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names))
    print('Constructed S1/P pass and S2/P fail reproduced in both entry orders.')


if __name__ == '__main__':
    main()
