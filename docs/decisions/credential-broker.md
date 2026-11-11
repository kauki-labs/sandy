---
title: "Decisions: credential broker"
status: proposed
project: sandy
updated: 2026-11-11
---

# Decisions: credential broker

How sandy's credential seam uses the `credential-broker` (#707, from #372 item 1). This record replaces the earlier
proposal of a sandy-owned injector. Sandy never terminates TLS for guest traffic: not in the egress proxy, and not in a
separate component.

**Status: proposed.** Nothing here is built. The owner's answers below reached this session through a peer relay
(sandy-63, 2026-11-11), not through a pinned or recorded owner comment. A recorded comment on #749 replaces the relay
when it exists.

## Context

Phase 1 stages the forge token as a `0600` file on the secret share ([`credential-seam.md`](credential-seam.md)
decision 2, [`sandyd.md`](sandyd.md) decisions 37 and 38). A hostile job can read it and send it out. Revoke and the
one-hour lifetime bound the damage; they do not prevent the leak.

The owner's answers on #749:

1. Minting is not sandy's job in the end. A separate repo, `kauki-labs/credential-broker`, stores secrets and holds the
   GitHub App keys. It has three delivery modes: A, a proxied call; B, a leased copy; C, an OIDC identity token.
2. One injector or one per run: moot, there is no injector.
3. A component that terminates TLS and reads guest plaintext is not acceptable. Redesign without it.
4. The first cut follows from what the broker offers.

## What the broker is today

From its README, `docs/overview.md`, `docs/decisions/` and `docs/design/credential-broker/` (read 2026-11-11):

- Status: design only. No service, no API contract, no deployment. The repo holds an interim operator-side token
  minter for the `external` App (`scripts/github-app-token`) and offline acceptance tests.
- A runner authenticates with an mTLS client certificate from an OpenBao PKI engine, short TTL (decision
  `mtls-runner-identity`). The broker explicitly names a sandy microVM as a runner type.
- The App key sits in OpenBao transit, non-exportable. A runner never holds it.
- The broker's policy maps `{identity, action, target}` to a credential type, a mode and the narrowest scope.
- Mode A: the runner holds a capability bound to its identity, action, target and expiry. A per-job proxy forwards the
  call with the broker-held token. REST uses a method and path allow-list. Git uses smart HTTP, and a push is allowed
  only to the ref in the capability. GraphQL is denied. The upstream token never reaches the runner.
- Mode B: a lease. The runner gets a credential, the broker records a lease, revokes it at release or expiry, and probes
  for a 401. A failed revoke marks the runner revoke-failed and denies it new leases (REQ-7).
- Mode C is a seam only.

## 1. Sandy is a client of the broker, not a holder of the App key

**Decision (recommended).** A new `CredentialProvider` implementation, `BrokerCredentialProvider`, in `sandy`. The
seam already has the right three verbs: `mint` is a lease request, `revoke` is a release, `refresh` is a renewal. The
trust-root registry (#592) gets a second kind, `broker`, beside the local GitHub App kind. A profile names a trust
root as today; the registry holds the broker address and the runner identity, never a key.

- The local App-key trust root stays. It is the path for a user with no broker, and phase 1 stays the path on the
  process backend, which has no secret channel for anything else.
- With a `broker` trust root the App key is not in sandy at all. That answers the earlier question of who mints: the
  broker, behind `sandyd`'s request.
- `sandyd` is a broker runner. It holds a short-lived client certificate and asks for a lease per run. The
  certificate's private key stays in `sandyd`, never in a guest.
- The bracket is unchanged: mint, stage, revoke, fail closed. A broker that is down or denies at mint refuses the run
  (decision 37). A revoke that fails is logged and reported as today.

## 2. First cut: mode B, a leased copy

The broker's mode B for a GitHub installation token fits the existing path and needs no guest change.

- `sandyd` leases the token, stages it as today, and releases the lease at teardown. The broker's ledger and probe
  replace sandy's own best-effort revoke.
- Renewal for an environment (decision 38) is a lease renewal. The order of decision 38 holds: stage the new token,
  then release the old lease. A failed renewal keeps the old token and does not release it.
- Cost: the token is in the guest again. A hostile job can still send it out until it expires or the broker revokes it.
  #745 (the vfkit guest can overwrite its staged token, which weakens the redactor) is unchanged for this mode. The
  gain is real but narrow: the App key is out of sandy, the lease is scoped to the run's repositories, and revocation
  has a probe.

## 3. Later: mode A, the guest never holds the upstream credential

This is the mode that closes the exfiltration. It works without any sandy component reading guest traffic.

- **Path.** The guest tool talks to the broker's proxy directly. Traffic leaves through the guest relay and the egress
  proxy as a CONNECT to the broker host on 443, and TLS runs from the guest to the broker. The egress proxy stays a
  CONNECT filter ([`egress-proxy.md`](egress-proxy.md) decision 4 stands). The broker host joins the run's egress
  allow-list; `github.com` need not be reachable for the actions the broker serves.
- **Guest tooling.** The guest holds a capability and the broker base URL, not a token. Git is pointed at the broker
  with `url.<base>.insteadOf` set through `GIT_CONFIG_COUNT` environment variables; the guest `gh` wrapper and
  `git-credential-sandy-gh` present the capability. Each client is its own slice and its own live row: a client that
  cannot take a base URL gets no credential. It does not fall back to anything weaker.
- **Guest identity.** The broker binds a capability to a client certificate. A microVM guest has none of its own. The
  recommended shape is a per-run certificate issued for the run and revoked at its end, which the guest holds. A guest
  can then use its capability and certificate for one action on one target until expiry; it cannot use the broker for
  anything else, and it holds no repository-wide token. This leaves a credential in the guest, a narrower one. It is the
  broker's decision whether `sandyd` may request a per-run certificate for a runner id. Needs an answer from the broker
  repo before this slice.
- **Set aside.** A host relay that takes plain HTTP from the guest over vsock and adds the mTLS to the broker. It reads
  guest plaintext, which the owner ruled out (answer 3). A TLS-intercepting proxy mode, ruled out earlier.
- This mode depends on broker blocks 2, 4 and 5, none of which exist.

## 4. Capability table

| Holder                 | Mode B                                      | Mode A                                           |
| ---------------------- | ------------------------------------------- | ------------------------------------------------ |
| Broker                 | App key (OpenBao), the lease ledger         | App key, per-job proxy, the installation token   |
| `sandyd`               | Its runner certificate, the leased token    | Its runner certificate, a per-run cert request   |
| Guest                  | The leased token, scoped to the run's repos | A capability and a per-run cert, one action each |
| Egress proxy           | Nothing, CONNECT filter                     | Nothing, CONNECT filter                          |
| Anything else in sandy | Nothing                                     | Nothing                                          |

No sandy component holds the App key under a `broker` trust root, and none reads guest TLS plaintext. The broker
reads a request only because the guest addressed it as the endpoint.

## 5. Failure and the revoke granularity

- **Broker unreachable or denying at mint:** the run is refused, no partial state (decision 37).
- **Renewal fails:** as decision 38. The old token stays until it expires; the credential path fails then.
- **Release fails:** the broker marks the runner revoke-failed and denies it new leases, retries, and alerts (REQ-7).
  If `sandyd` is one runner, a single failed release stops every run on the host. The runner identity must therefore be
  per run, or per profile, not per host. This is an open point for the broker, owner decision 3 below.
- **Lease record lost:** the token still expires by its own lifetime; the broker reports an orphan.
- **`sandyd` crashes:** the leases expire by TTL, and the broker revokes them by runner certificate expiry.

## Adversarial pass

| Attack                                                       | Answer                                                                                                    |
| ------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| Hostile job reads the leased token (mode B)                  | Succeeds. Bounded by the lease scope, the lifetime and the broker's revoke. Not closed in this mode       |
| Hostile job replays a capability on another repo or ref (A)  | The broker refuses: the capability is bound to action, target, identity and expiry (broker REQ-8)         |
| Hostile job uses its per-run cert for another action (A)     | Refused by policy: deny by default, narrowest scope                                                       |
| Guest supplies its own `Authorization` toward the broker     | The broker strips it and uses its own token (broker block 5)                                              |
| Guest floods the broker                                      | The broker throttles per runner; the egress proxy's own caps apply to the CONNECT                         |
| One run's failed release locks out every run                 | Per-run or per-profile runner identity; open point                                                        |
| Broker compromise                                            | It holds the App keys of every installation it serves. Its custody is the broker's own decision record    |
| The broker is down                                           | Runs with a `broker` trust root refuse to start. The local trust root still works                         |
| `sandyd` runner certificate is stolen                        | The thief can lease for the policy's repositories until the certificate expires; short TTL, broker revoke |
| A later non-GitHub upstream echoes the request in a response | Not a sandy matter in this shape; the broker's per-upstream proxy checks it                               |

## Work, in order

1. Ask the broker repo for a lease API (mint, renew, release, revoke-all) and typed errors. Sandy cannot start
   without a contract; the broker has none.
2. `BrokerCredentialProvider` against a fake broker (tier 2), the `broker` trust-root kind, and the registry entry.
3. A live row against a real broker once one exists.
4. The redactor: under mode B the staged file is read as today. Under mode A the secret to mask is the capability, and
   `sandyd` holds a copy in memory, which touches `cred_bracket.rs`. #745 closes for mode A only after that lands.
5. Mode A, one client at a time: `git`, then the `gh` wrapper. The live row proves the tool works with no token in the
   environment or on the share, and scans the share and the console for the capability.

## Consequences

- INV-1 gets no new exception. No sandy process reads guest plaintext.
- #706 and #708 do not wait on this. Decision 38's option C (`sandyd.md`) is now mode A of the broker, not a sandy
  component.
- Cross-repo, for the broker to amend (not edited here): its spec's escalation appendix and its proposal name a
  TLS-terminating egress proxy (sandy #372) as a fallback. The owner ruled that out.

## Owner decisions needed

1. **Record the answers.** The four above reached me by relay. Post them as a recorded comment on #749 (or the pinned
   decisions comment) so the record can cite them.
2. **First cut.** Recommended: mode B through `BrokerCredentialProvider`, then mode A per client.
3. **Runner granularity.** Recommended: one broker runner identity per run (or per profile), so a failed release
   cannot freeze the host. It needs a broker answer.
4. **A per-run client certificate in the guest** for mode A. Recommended, because the capability is bound to a
   certificate. It leaves a narrow credential in the guest. The alternative is a plaintext host relay, which answer 3
   forbids.
