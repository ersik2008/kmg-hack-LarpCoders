# KMG Security Test Repository & Fixtures

This repository contains real vulnerable and clean code fixtures designed for automated testing, regression tests, and security demonstration across the following categories:

- `sql-injection/`: Unsanitized input concatenation into raw SQL.
- `command-injection/`: Shell execution with user input concatenation.
- `ssrf/`: HTTP request dispatch to arbitrary target URLs.
- `xss/`: Unescaped reflective comment in HTTP response.
- `path-traversal/`: Arbitrary filesystem path reading.
- `secrets/`: Exposed AWS keys, GitHub PATs, and DB URIs.
- `weak-crypto/`: Insecure MD5 hashing and pseudo-random numbers.
- `insecure-auth/`: Unverified JWT decode and IDOR account deletion.
- `vulnerable-dependencies/`: Manifest with out-of-date vulnerable libraries.
- `insecure-config/`: Debug flags and permissive CORS wildcards.
- `clean/`: Hardened, secure code patterns (parameterized queries, PBKDF2 hashing).
