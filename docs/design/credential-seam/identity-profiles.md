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

- A profile name has 1 to 64 characters from `A-Za-z0-9`, `-`, `_`, `.`. It does not look like a credential.
  This is the rule sandyd applies to the request's `profile` field, so a registry name always passes the request check.
- `credential` is a name of the same character set and the same length bound.
- `targets` has 1 or more entries. Each entry is a non-empty provider path with no whitespace or control
  character.
- `capabilities` has 1 or more entries, each a `Capability`. Duplicates are removed.
- `service_secrets` is a list of names that match `[A-Z][A-Z0-9_]{0,63}`.

### Expected outputs

- `IdentityProfiles::parse` returns the registry or the first error.
- `IdentityProfiles::resolve(name)` returns the `IdentityProfile` for a known name.
- `IdentityProfile::scope()` returns the `Scope`. `IdentityProfile::credential()` returns the trust root name.
  `IdentityProfile::service_secrets()` returns the names.
- The registry is an array, so a duplicate name is detectable (a JSON object keeps the last of two equal keys).

### Failure definition

- An unknown field is an error (`deny_unknown_fields`). A key named `token`, `secret` or `password` therefore
  fails the parse. The error names the field, never a value.
- An empty list, a malformed name or a duplicate profile name is an error that names the profile.
- `resolve` of an unknown name returns `UnknownProfile`. It does not list the known names.
- No error text contains a value taken from the file, except the profile name the caller asked for.
- A registry that fails to parse stops the daemon start. It never starts with a partial registry.

### Performance and scale

The registry has tens of profiles and is read once. `resolve` is a map lookup.

### Dependency behaviour

- The registry does not call a provider. A name in `credential` that has no trust root fails at mint time
  (a later slice), not at parse time, because trust roots live on the host and the registry is portable.
- `Capability` and `Scope` come from `sandy-api` unchanged.

### Out of scope

- Re-injection at start and resume, renewal over the agent link, revoke on stop and delete. They need #587.
- The broker `profile` field and the OpenAPI contract. sandyd already validates the name shape
  (`crates/sandyd/src/environment.rs`); a later slice makes it call this module so there is one rule.
- Per-client authorization of a profile (#596).

## AI-gap self-test

If an agent built this, passed the tests and still behaved wrong, the gap would be one of:

- A profile with a `token` key parses because unknown keys are ignored. The tests parse such a file.
- `service_secrets` defaults to "all secrets". The tests assert that the default is empty.
- An error echoes a rejected value into a log. The tests assert that the error text omits the value.

## Acceptance tests (tier-2)

1. A valid registry resolves a profile to the expected scope, trust root and service secrets.
2. A key named `token` fails the parse and the error does not contain the value.
3. An unknown profile name returns `UnknownProfile` and the error lists no other name.
4. An empty `targets`, an empty `capabilities`, a bad secret name and a duplicate profile name each fail.
5. `service_secrets` absent means the empty list.
6. A profile name that looks like a credential is refused.
