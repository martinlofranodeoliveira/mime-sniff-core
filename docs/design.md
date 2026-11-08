# Design — mime-sniff-core

Rules are exact byte predicates with a minimum length; a truncated
header (e.g. 2-byte `PK`) yields `null` instead of a premature ZIP.
When several rules could match, the longest minimum-length wins
(deterministic, no priority table to maintain).

Oracle: real-world magic numbers per format, truncated-input nulls,
and the ID3-vs-frame-sync MP3 pair. Extension output only — no
content parsing beyond the signature window.
