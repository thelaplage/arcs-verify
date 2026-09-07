# SCITT-VECTORS0

**Status:** downstream test lane scaffold  
**Base:** exact `SCITT-VERIFY0` head at branch creation  
**Authority movement:** `0`

This branch exists only to add independently sourced SCITT interoperability
vectors after the verifier contract is reviewed. It must not change verifier
semantics.

Required vector provenance for every imported artifact:

- upstream repository;
- exact upstream commit;
- source path;
- license;
- exact SHA-256;
- expected pass/fail interpretation.

Priority sources are independent IETF/Microsoft/reference vectors. Vectors
produced solely by the same `scitt-cose` package used as the neutral runtime
substrate are useful regression material but are not sufficient by themselves
as an independent oracle.

No vector bytes are imported in this scaffold commit. That remains a separate
review step after `SCITT-VERIFY0` settles its report shape.
