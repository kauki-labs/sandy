---
title: "Decisions: credential injector"
status: proposed
project: sandy
updated: 2026-11-11
---

# Decisions: credential injector

Phase 2 of the outbound credential layer (#707, from #372 item 1): the exit for the forge token that phase 1 puts in
the guest ([`credential-seam.md`](credential-seam.md) decision 2, [`sandyd.md`](sandyd.md) decisions 37 and 38). The
owner decided on 2026-11-10 (recorded on #707) that the INV-1 exception for TLS termination in the egress proxy is not
granted. Injection is a separate, centralized component with its own credential capabilities, and the egress proxy
stays a CONNECT filter ([`egress-proxy.md`](egress-proxy.md) decision 4 stands). #706 and #708 do not wait on this.

**Status: proposed.** Nothing here is built. Section "Owner decisions" lists what a reader must settle before code.

## Context

Phase 1 stages the token as a `0600` file on the secret share. A hostile job can read it and send it out. Revoke and
the one-hour lifetime bound the damage; they do not prevent the leak. The fix is that the guest never holds the
token: something on the host adds the credential to a request after the request has left the guest.

That something must read the request, so it terminates TLS for the hosts it serves. That reach is the reason it is not
the egress proxy. The proxy's contract is "no plaintext, no credential, an allow-list on the CONNECT target". The
injector's contract is the opposite: it holds credentials, reads plaintext for a few named hosts, and does nothing
else.

## 1. The injector is its own host process, one per host, with per-run listeners

**Decision.** A new binary `sandy-injector`, run by `sandyd` as a child (like the egress proxy, but one process for
all runs on the host, not one per run). It is not a mode of `sandy-egress-proxy` and shares no code path with its
CONNECT handling. It owns three things: the CA key, the credential sources and the rule table.

- **Per-run listener.** `sandyd` registers a run with the injector over a private Unix socket. The injector opens a
  listener for that run: a vsock port scoped to the run's CID on qemu, a Unix socket in the run's private staging
  dir on vfkit (the same two shapes as the egress proxy, `egress-proxy.md` decision 2). A run reaches only its own
  listener, so the listener is the run's identity. A connection carries no claim that the injector trusts.
- **Grant.** The registration carries the run's grant: a list of rules `host -> header, source`, a CA name constraint
  equal to the rule hosts, and the credential source for each rule. It is dropped when the run ends, and the
  listener closes with it.
- **Guest routing.** The guest relay (`sandy-agent`, an existing component, no T3 code) already runs the CONNECT
  relay for the job. For a CONNECT target that is a rule host it connects the tunnel to the injector listener instead
  of the egress proxy. For every other target it does what it does today. The relay learns the rule hosts from its
  launch settings. A guest that bypasses the relay can reach the same listener and nothing else.
- **No allow-list fork.** `sandyd` refuses a grant whose rule host is not in the run's egress allow-list, so the
  injector cannot widen what the run may reach. The two lists come from one spec.

**Why not the proxy.** The owner ruled it out. It also keeps the blast radius apart: a bug in the CONNECT parser must
not sit next to a CA key and a live token.

**Set aside.** TLS termination as an optional proxy mode. A per-run injector process (a CA and a process start per
run, which is what `egress-proxy.md` decision 2 chose for the proxy: small, unprivileged, scoped to one run). A
guest-side injector (the guest would hold the credential again).

**The cost of "centralized".** One process for all runs holds every live run's token. That departs from the per-run
scoping of the egress proxy, and a bug in it reaches every run on the host (see the adversarial pass). The owner asked
for a centralized component; the per-run listeners and per-run grants keep the runs apart inside it, but they are not
process isolation. A per-run process is the alternative if the owner prefers that boundary (Owner decision 2).

## 2. What the injector may do: its capability model

The injector is the only component that holds a live forge token for a run while the run is live. Its capabilities are
narrow and listed, so a review can check them.

| Capability                  | Held how                                                                                |
| --------------------------- | --------------------------------------------------------------------------------------- |
| Read a rule's credential    | From the source named in the grant, in memory only, never on disk, never in a log       |
| Sign a leaf for a rule host | The CA key, in the injector process only, never written out, generated at process start |
| Reach a rule host upstream  | Host network, only the hosts in some live grant, only port 443                          |
| Read a request from a run   | Only on that run's listener, only for a rule host                                       |
| Mint a token                | **Not held** in the recommended shape (decision 3); see Owner decisions                 |

It has no capability to read a run's files, start a VM, write the journal, or reach a host that is in no grant.

## 3. Credential sources: `sandyd` mints, the injector holds the token in memory

**Decision (recommended).** `sandyd` stays the only reader of the trust root. For a run that has an injector grant it
mints through `EnvironmentCredentials` or the job bracket as today, but it does not stage the token on the secret
share. It hands the token to the injector over the private registration socket, and again at each renewal. The
injector keeps the latest token per grant in a zeroizing buffer. `sandyd` still revokes: the lease and the revoke
path of decisions 37 and 38 do not change. The injector never mints, so the App private key never leaves `sandyd`.

Consequences:

- No token file in the guest, so the guest-side refresh of decision 38 is not needed for injected hosts, and the
  vfkit masking gap (#745) closes for them: there is no staged copy for a guest to overwrite. The host keeps a
  host-only copy for the redactor, as today.
- The renewal margin is host-side only. A renewal is one message on the socket.
- The injector holds a token in memory, so a crash loses it. `sandyd` notices the socket close, restarts the injector
  and re-registers every live run with a fresh mint. Until then requests to rule hosts fail with 502 (section 5).

**The owner's words and this shape.** The owner said "its own credential capabilities". Read strictly, that means the
injector reads the trust root and mints for itself. That removes the push from `sandyd` and puts the App private key
into a second process that terminates TLS for guest traffic. This record recommends against it: the process that
reads untrusted plaintext should not also hold the minting key. It is the first Owner decision.

**Set aside.** Staging the token on the share and having the injector read it (the guest could read it too). A
long-lived token pushed once (a GitHub token is revoked by itself only, and lives about an hour).

## 4. TLS: a CA in the injector, a public certificate in the guest

- **CA.** One CA per injector process, generated at process start, name-constrained to the union of rule hosts of the
  live grants. The private key lives only in the injector's memory. A restart makes a new CA, and every live run gets
  the new certificate. Per-run CAs were considered: they narrow what a leaked leaf can impersonate, but a leaked CA key
  is the real loss, and that key never leaves the process either way. One CA is simpler. A name constraint per run is
  still applied by the leaf rule, not the CA.
- **Guest trust.** The guest gets the CA certificate only, as a public file on the share. The relay sets
  `GIT_SSL_CAINFO`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS` to it for the job. No guest image
  change. A client that does not honor these (a pinned client, a tool with its own bundle) fails its own connection
  and gets no credential. That is a safe failure.
- **Leaves.** Minted on demand for the SNI, only for a rule host of that run's grant, cached per host per run.
  HTTP/1.1 only. Bodies stream, so a large git pack is never buffered.
- **Upstream.** The injector opens its own TLS connection to the real host and verifies it against the system roots.

## 5. Request handling and failure

- For a rule host the injector sets the rule's header on every request. A header from the guest of the same name is
  overwritten, never forwarded, and so is a duplicate. The credential format is part of the rule: git over HTTPS wants
  `Authorization: Basic base64(x-access-token:<token>)`, the REST API accepts `Authorization: Bearer <token>`.
- The `Host` header must equal the SNI the tunnel was opened for. A mismatch is refused: a request must not borrow
  the credential of one host for another (domain fronting).
- A redirect to a host with no rule is not followed by the injector. The client follows it itself, on the egress
  proxy, and gets no credential.
- A source that cannot supply a token answers the request `502` with a fixed reason that names no secret. The run does
  not fail. A run that cannot clone is a visible, ordinary failure.
- Limits: 64 concurrent terminated connections per run, further ones queue; a per-connection idle timeout as in the
  bridge.
- Never: a header value, a token, or a request body in a log, an error, a receipt or a metric. The injector logs the
  run, the host and the status class.

## Adversarial pass

| Attack                                                                   | Answer                                                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Guest sends its own `Authorization`, a second `Host`, or `X-Forwarded-*` | The rule header overwrites; a `Host` that is not the SNI is refused                                                                                                                                                                                    |
| Guest asks a rule host for a path it should not have (another repo)      | The token's scope (the profile `Scope`) decides; the injector adds no path ACL yet                                                                                                                                                                     |
| Guest reads the CA key                                                   | The key is in injector memory only; the share has the certificate                                                                                                                                                                                      |
| Guest uses the CA to impersonate a host to something else                | The CA is name-constrained to rule hosts, and only this guest trusts it                                                                                                                                                                                |
| Guest opens a tunnel to a rule host of another run                       | It cannot reach another run's listener                                                                                                                                                                                                                 |
| Guest floods the injector                                                | 64 connections per run, a global cap, an idle timeout                                                                                                                                                                                                  |
| Injector compromise (a TLS or HTTP parser bug)                           | It holds the live tokens of every run on the host and the CA key. This is the central risk of the design: the injector is a new, high-value process. Keep it small, `forbid(unsafe)`, no plugin or config surface, no outbound reach except rule hosts |
| `sandyd` or the socket is gone                                           | The injector drops every grant and answers 502 until re-registered                                                                                                                                                                                     |
| Token leaks to the guest anyway (a header echoed back in a response)     | The injector strips its own header from responses and does not forward `Authorization` from upstream                                                                                                                                                   |

The path-ACL row is a gap: with a token scoped to the profile's repos the injector is no weaker than phase 1, and it
removes the exfiltration, but it does not narrow what a hostile job can do with the token while the run lives. A path
rule per host is a later option.

## Consequences

- INV-1 gets a stronger form for injected hosts: the token never reaches the guest at all. The injector reads
  plaintext for rule hosts, which the egress proxy never does. That exposure is the cost the owner chose to put in a
  separate component rather than in the proxy.
- Phase 1 stays as the fallback and as the only path on the process backend, which has no vsock and no injector
  listener.
- New work, in order: the injector's rule and header core (pure, tier-2 tests); the CA and leaf minting; the
  registration socket and the per-run listeners; the guest relay's routing and env; the `sandyd` wiring that stops
  staging the token; the live row (`git clone` and `git push` from a guest with no token in its environment or on its
  share, and a byte scan of the share and console for the token).

## Owner decisions needed

1. **Who mints.** Recommended: `sandyd` mints and pushes the token (decision 3), so the App key stays in `sandyd`.
   Alternative, from the owner's phrase: the injector reads the trust root and mints. This is a public security
   boundary choice.
2. **One injector per host or one per run.** Recommended: one per host (centralized, as the owner said), with
   per-run listeners.
3. **Confirm the injector's contract.** It reads TLS plaintext for the rule hosts of its runs, and for nothing else.
   This is the INV-1 exposure the owner declined for the proxy. It needs a sentence in the invariants list that says
   it belongs to the injector.
4. **Scope of the first cut.** Recommended: `github.com` and `api.github.com` for the profile's forge token only; model
   API keys and operator secrets (#705) as later rules on the same table.
