# Security policy

sandy runs untrusted jobs in an ephemeral microVM and hands back a locked result
envelope. Its security boundaries, the guest/host isolation, the read-only input
and secret shares, the fail-closed credential mint, and the egress allow-list are
load-bearing, so we take reports against them seriously.

## Reporting a vulnerability

Report privately, not in a public issue:

- Preferred: GitHub's private vulnerability reporting on this repo, under
  **Security → Report a vulnerability**
  (<https://github.com/kauki-labs/sandy/security/advisories/new>).
- Or email **tibor.csoka@kauki.xyz** with the details.

Please include a description, the affected version or commit, and the smallest
steps that reproduce it. A proof of concept helps; a working exploit is not
required, and we would rather you not post one publicly.

We aim to acknowledge a report within three working days and to agree a
disclosure timeline with you. We will credit you in the advisory unless you ask
us not to.

## Scope

In scope: anything that lets a guest job reach the host, read another run's
inputs or secrets, escape the egress allow-list, obtain a credential it was not
minted, or make the result envelope misreport the outcome.

Out of scope: issues that require an already-privileged host, the documented
macOS egress no-op, and the behaviour of the job's own payload.

## Supported versions

sandy is pre-1.0. Fixes land on the latest released version; there is no
backport channel yet.
