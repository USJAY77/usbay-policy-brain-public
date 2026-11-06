# Public signed CRL vectors

Source: pyca/cryptography, commit 9f119db1beba2834af325cc631b3d787b895943d,
vectors/cryptography_vectors/x509/PKITS_data/{certs,crls}.
Public DER vectors are stored in ../public-x509-vectors.json and decoded to
in-memory public PEM with cryptography's native parser and serializer. Upstream Git blob identities and derived hashes are recorded in
evidence. No private keys are fetched. Upstream license notice is retained.

Tests evaluate this chain at 2010-01-01T08:31:00Z, shortly after its signed CRLs'
thisUpdate, with an explicit one-hour CRL-age profile. They separately prove that
the same old CRLs fail the current-clock age check. Historical positive tests do
not establish current revocation evidence or production TSA trust. The chain is
different from the public sigstage timestamp chain; matching timestamp/CRL
composition is tested separately with memory-only synthetic signing keys.
