"""Execute installed CLI from outside the source tree, with networking disabled."""
import json
import subprocess
import sys
from pathlib import Path

import arcs_verify
from arcs_verify import dagr_report as dr
from arcs_verify import scitt_registration as v
from arcs_verify.verifier import verify_receipt

source = Path(__file__).resolve().parents[1]
installed = Path(arcs_verify.__file__).resolve().parent
assert source not in installed.parents, 'smoke must load the installed wheel, not checkout'
fixtures = source / 'docs/scitt-offline/constructed'
cli = str(Path(sys.executable).parent / 'arcs-verify')
for order in ('forward', 'reverse'):
    result = subprocess.run([cli, 'scitt-registration', str(fixtures / f'{order}-sidecar.json'),
                             '--artifact', str(fixtures / 'artifact.json'), '--selection', str(fixtures / 'selection.json')],
                            check=True, capture_output=True, text=True)
    assert json.loads(result.stdout) == json.loads((fixtures / f'{order}-report.json').read_bytes())
print('Installed SCITT CLI: both retained reports exactly reproduced.')
golden = dr._CONTRACT_ROOT / 'golden'
assert dr.validate_verification_report(json.loads((golden / 'admission-report.json').read_bytes())) == []
assert dr.validate_verification_execution_record(json.loads((golden / 'admission-execution-record.json').read_bytes())) == []
srs = json.loads((golden / 'admission-receipt.json').read_bytes())
keyring = json.loads((golden / 'trust-bundle.json').read_bytes())
assert verify_receipt(srs, keyring, schema_path=installed / 'data/srs-envelope-v0.2.1.schema.json').passed
result = subprocess.run([cli, 'dagr-report', str(golden / 'admission-receipt.json'), '--keyring', str(golden / 'trust-bundle.json'),
                         '--verifier-commit', '9e6daefca6e77306691fd288880448194bd28f75', '--execution-id', 'exec:constructed:scitt-smoke',
                         '--executed-at', '2026-10-13T00:00:00Z'], check=True, capture_output=True, text=True)
print('Installed legacy SRS verification and DAGR contract/CLI: passed.')
print('SCITT handoff:', v._contracts()[1]['verifier-handoff.json']['status'])
print('Installed import came from wheel environment, outside source checkout.')
