# Decisions: credential seam (`CredentialProvider`)

Minting a short-lived, least-privilege forge token for a job, delivering it
in-guest, refreshing it mid-run, and revoking it at teardown. Subsystem spec:
[`../architecture/spec.md#4-credential-seam-credentialprovider`](../architecture/spec.md#4-credential-seam-credentialprovider).

## 1. Mint → stage → revoke bracket, fail-closed

**Status:** accepted. **Upholds:** INV-7.

**Context.** A job that needs a forge token must never run without one when one
was requested, and a token must never outlive the job.

**Decision.** `run_job_with_credential` mints **before** boot; a mint failure
returns an infra fault with **no boot**. The lease is revoked on every path (ok,
error, kill).

**Consequences.** A credentialed run is all-or-nothing: either the token exists
and is delivered, or the run fails closed as infra (retryable), never a degraded
run with a missing token. Proven live by K10.

**Set aside.** Best-effort mint (boot anyway, hope the token shows up): rejected,
it would turn a credential outage into a silent task failure.

## 2. Trust root, not a shared server

**Status:** accepted. **Upholds:** INV-1 (the minted token is a secret).

**Context.** Handing every job a long-lived shared token is a broad blast radius;
a central token-minting service is another thing to run and secure.

**Decision.** The provider is a GitHub App whose private key stays on the
controller (`sandy cred github register/import/verify/deregister`). Each job mints
an **installation token** scoped to its repos/capabilities. The minted token is a
secret, delivered over the secret channel.

**Consequences.** Each job gets a narrow, short-lived token; the trust root never
leaves the controller. The provider is a seam (`CredentialProvider`), so GitLab
or another forge is a new adapter.

## 3. Mid-run refresh

**Status:** accepted.

**Context.** A job can outlive an installation token's TTL, and `git credential
fill` must keep serving a valid token without the job seeing it on argv or console.

**Decision.** A refresh thread with a large margin and short tick re-mints and
rewrites the live secret file; the guest's `git credential fill` serves the fresh
token.

**Consequences.** A long job keeps working across token expiry; the value is never
exposed on argv/console. Proven live by K11 (`live_refresh.rs`), which refuses on
default margins rather than skip-greening (INV-S9).
