# API contract status

The normative protocol is implemented in `rp-protocol` and versioned test
vectors.  Until M1 lands, this directory intentionally contains no informal
JSON or HTTP examples that could be mistaken for authorization behavior.

The future local API is length-prefixed CBOR over `SOCK_SEQPACKET`; the hosted
API is HTTPS under the official approval origin.  Neither API accepts a shell
command, APT flags, package URL, repository, filesystem path, or client
asserted identity.
