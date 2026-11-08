# Identity profiles (#592, epic #597)

An environment request names an identity profile. It never carries a secret. The broker resolves the
profile to a credential scope and to the secret names the service may read. This document specifies
slice 1: the profile registry and its validation. Re-injection on start, renewal over the agent link and
revoke on stop are later slices, because they need the environment lifecycle (#587).

The profile layer sits above the credential seam (`sandy_api::cred`, `sandy::cred`). It does not mint, refresh
or revoke. It decides what a mint is for.

## Registry

The operator writes the registry. It is a JSON file read at daemon start. It holds names, never values.

```json
{
  "profiles": [
    {
      "name": "dev",
      "credential": "github-main",
      "targets": ["owner/repo"],
      "capabilities": ["read_code", "write_code"],
      "service_secrets": ["GITHUB_TOKEN"]
    }
  ]
}
```

- `credential`: the name of a registered trust root (`sandy cred <provider> register`).
- `targets`, `capabilities`: the `Scope` of the minted credential. The repository allow-list is `targets`.
- `service_secrets`: the secret names exported to the service process. The default is the empty list.
  The service reads only these names (#632). The secret directory stays root-only (`0700`).

## Specification

### Valid inputs

- A profile name has 1 to 64 characters from `A-Za-z0-9`, `-`, `_`, `.`, and starts with a letter or digit, so `.`
  and `..` are never a name. It does not look like a credential (a known prefix such as `ghp_` or `sk_`, or 32 or
  more hex digits; see the limit below). This is sandyd's rule for the request's `profile`
  field, plus the leading character, so a registry name always passes the request check. Names that differ only in
  ASCII case are one name when the registry loads, but `resolve` compares the exact name, as sandyd does.
- `credential` is the name of a registered trust root: any single file name that trust-root registration accepts (not
  empty, not `.` or `..`, no `/` or NUL), up to 64 bytes, with no control or bidi character. It does not look like a
  credential. It is looser than a profile name on purpose: a profile must be able to name every root registration
  creates, such as `_github-main`.
- `targets` has 1 to 256 entries. Each entry is an `owner/repo` path (nested groups allowed) of ASCII letters, digits,
  `-`, `_`, `.` and `/`, up to 256 bytes, with no empty segment and no `.` or `..` segment. A URL, a leading `/`, a
  bare name and any non-ASCII character are refused, so the visible path is the path that is allowed. A repeated
  entry is kept once.
- `capabilities` has 1 to 256 entries, each a `Capability`. Duplicates are removed.
- `service_secrets` has up to 256 names that match `[A-Z][A-Z0-9_]{0,63}` and do not look like a credential.
  Duplicates are removed, in order.
- A registry file is at most 1 MiB and holds at most 1024 profiles. The size is checked before the parse.

### Expected outputs

- `IdentityProfiles::parse` returns the registry or the first error.
- `IdentityProfiles::resolve(name)` returns the `IdentityProfile` for a known name.
- `IdentityProfile::scope()` returns the `Scope`. `IdentityProfile::credential()` returns the trust root name.
  `IdentityProfile::service_secrets()` returns the names.
- The registry is an array of named entries, so a duplicate profile name is detectable. A repeated key inside an
  object is refused too (`serde_json::Value` would keep the last one, and the file a reviewer reads would differ from
  the registry that loads).

### Failure definition

- An unknown field is an error. A key named `token`, `secret` or `password` therefore fails the parse. The error
  says a field is unknown and lists the allowed fields. It never shows the key, because a pasted secret can sit
  where a key belongs in a shape no prefix list knows.
- An empty `targets` or `capabilities` list, a malformed name or a malformed entry is an error that gives the entry's
  position and the rule it broke. A duplicate profile name is an error that gives both positions. No error shows a name.
- A repeated key is a `Malformed` error with the line and column.
- `resolve` of an unknown name returns `Unknown`. The error shows neither the asked name nor the known names.
- No error text contains any string taken from the file or from the caller. The only text is a fixed message with
  an entry position or a line and column.
- A registry that fails to parse stops the daemon start. It never starts with a partial registry.

### The limit of the credential-shape check

The check that refuses a name that "looks like a credential" knows a list of prefixes and one generic shape (long hex).
It is a best-effort guard against a paste, not a guarantee: a secret in another shape passes it. The contract is that
the registry holds names only. The error texts never show a key, a name or a value, so a pasted secret does not reach a
log through them. The types derive `Debug`, which prints the names that were accepted, so no caller logs a profile.

### Performance and scale

The registry has tens of profiles and is read once. `resolve` is a linear scan, which is enough at that size.

### Dependency behaviour

- The registry does not call a provider. A name in `credential` that has no trust root fails at mint time
  (a later slice), not at parse time, because trust roots live on the host and the registry is portable.
- `Capability` and `Scope` come from `sandy-api` unchanged.

### Operator secret store (#705)

A `service_secrets` name that no provider mints takes its value from the operator's store directory: one file per name. The environment variable that names it
is chosen when the store is wired (`SANDY_SECRETS_DIR` is taken: it is the job-side path of the staged secret share).
`sandyd::operator_values::SecretStore` reads it and nothing else does.

- Open: the directory is opened once, without following a symlink (a trailing `/` is dropped first), and
  must be this user's and not group- or world-writable. The handle is kept: every read goes through it, so a
  swap of the path after open is not followed.
- Read: the name must match `[A-Z][A-Z0-9_]{0,63}` before any name is used. The leaf is opened relative to the
  held directory without following a symlink and must be a regular file owned by this user, mode `0600` or
  tighter (no group, other, execute, setuid, setgid or sticky bit), at most 64 KiB. The buffer is zeroed first,
  sized once, read into directly and zeroed on drop. A file that grows or shrinks during the read is refused.
- Errors name the secret, never the value, the text of a bad name, or the OS message.
- Left to the staging slice: whether an empty file is an error and whether one trailing newline is trimmed
  (`echo key > FILE` writes one). The store returns the file bytes as they are. A macOS ACL can grant access
  without changing the mode bits, and the store does not check ACLs.
- Not yet: staging on the environment's secret share at start and resume, and the registry check that a
  minted name and a stored name do not clash. They need #704 and #706.

### Out of scope

- Re-injection at start and resume, renewal over the agent link, revoke on stop and delete. They need #587.
- The broker `profile` field and the OpenAPI contract. sandyd already validates the name shape
  (`crates/sandyd/src/environment.rs`); a later slice makes it call this module so there is one rule.
- Per-client authorization of a profile (#596).

## AI-gap self-test

If an agent built this, passed the tests and still behaved wrong, the gap would be one of:

- A profile with a `token` key parses because unknown keys are ignored. The tests parse such a file.
- A secret pasted as a key, a name or a value is echoed because the "safe to show" check knows only some
  prefixes. The tests put seven shapes of secret in a key and one in every known field, and no error shows one.
- Two keys in one object load as the last one. The tests parse duplicates inside an entry and at the top level.
- A target such as `../x` or a URL is accepted and later widens a scope. The tests refuse them.
- `service_secrets` defaults to "all secrets". The tests assert that the default is empty.
- An error echoes a rejected value into a log. The tests assert that the error text omits the value.

## Acceptance tests (tier-2)

1. A valid registry resolves a profile to the expected scope, trust root and service secrets.
2. An unknown key, in seven shapes, fails the parse and the error does not contain the key.
3. A secret in any known field fails or is refused and the error does not contain it.
4. An unknown profile name returns `Unknown` and the error shows neither it nor another name.
5. Each broken entry fails with the stated reason: empty or traversing targets, a bad capability, a bad name or
   credential, a bad secret name, a list over its bound. A missing field is refused for that field.
6. A repeated key, a duplicate profile name (also differing in case) and more than 1024 profiles are refused.
7. `service_secrets` absent means the empty list. Repeats are removed in order.
