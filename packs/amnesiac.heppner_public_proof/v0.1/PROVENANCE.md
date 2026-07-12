# Provenance

`producer/proof_bundle.json` was regenerated from merged arcs-amnesiac main at
commit `1dc7660` and matched the verifier fixture byte-for-byte before this pack
was prepared.

`producer/garpedia_projection.json` is the public projection emitted by that
walkthrough. ARCS Verify does not treat the GARPedia projection as a source of
truth and does not import producer code.

ClaimGraph snapshots retain ClaimNode and ClaimEdge `created_at` fields because
they participate in the graph substrate hash. Packet, walk, render, and
inspection audit timestamps remain outside their canonical object hashes.
