# Policy and rules

This page explains how Secret Guardian decides what to do with a request: roles, the `Unmatched`
policy, rules and their validation, host and method matching, and in detail how request paths are
judged. Sources: `crates/policy/src/{model,store,matcher,normalize,render}.rs`,
`crates/proxy/src/{server,forward,inject}.rs`, and the tests in `crates/policy/` and
`crates/proxy/tests/inject.rs`. The spec reference is section 6.2 of
[`docs/specs/2026-10-16-secret-guardian-vault.md`](specs/2026-10-16-secret-guardian-vault.md).

There is no CLI or admin API yet (planned). Rules are created through the `sg_policy` functions
(`add_role`, `add_rule`); the JSON shape shown in section 9 is the `serde` shape of `NewRule`.

## 1. Roles and the `Unmatched` policy

A **role** is a name plus an `Unmatched` policy (`crates/policy/src/model.rs`, `store.rs`):

- Role name: 1 to 64 bytes of `[a-z0-9_-]` (`add_role`); unique (`AlreadyExists` otherwise).
- `Unmatched::Passthrough` or `Unmatched::Deny`, stored as the strings `passthrough` / `deny`
  (a `CHECK` constraint in the schema). There is no default in the library: `add_role` requires one.
  An unparsable stored value is read as `Deny`.
- Deleting a role deletes its rules (`ON DELETE CASCADE`). Tokens are not touched: a token whose role was
  deleted still verifies but every CONNECT gets `403` with audit decision `unknown-role`.

The policy applies **at CONNECT time, per host** (`crates/proxy/src/server.rs`, `connect`):

| Does the role have any rule whose host pattern matches the host? | Result |
|---|---|
| Yes | The proxy terminates TLS (MITM). Each inner request is then judged by `evaluate` (sections 4 to 7). |
| No, role is `Deny` | `403`, audit `unmatched-denied`. |
| No, role is `Passthrough` | Opaque TCP tunnel to the destination, no TLS termination, no injection (audit `passthrough`). |

Note that the question is "any rule for the host", ignoring path and method. Inside a MITM tunnel, a
request that matches no rule gets `403` (`forbidden`), even if the role is `Passthrough`:
passthrough is a per-host decision, not a per-request one.

## 2. Rules

A rule says: for this role, for requests matching host / path / methods, inject this secret this way.

| Field (`NewRule`) | Type | Default | Meaning |
|---|---|---|---|
| `role` | string | required | Must exist. |
| `host_pattern` | string | required | Exact hostname or `*.hostname` (section 3). |
| `path_pattern` | string | `"*"` | `*`, an exact path, or a prefix ending in `*` (section 6). |
| `methods` | list of strings | `[]` | Empty means any method. Stored upper-cased, comma-joined. |
| `kind` | `"header"` or `"query"` | required | Where to inject. |
| `target_name` | string | required | Header name or query parameter name. |
| `template` | string | required | Value template; must contain `{secret}`. |
| `secret_id` | integer | required | Must exist; the secret cannot be deleted while a rule uses it. |

### 2.1 Validation (`store.rs`, `validate`)

All of these are checked by `add_rule`; a failure is `PolicyError::Invalid(..)`:

- **`host_pattern`** (`valid_host_pattern`): all lower case; either `host` or `*.host` with exactly one
  leading `*.` and no other `*`; labels non-empty and made of `[A-Za-z0-9_-]`; must contain at least one
  letter; must not be an IP literal (so no IPv4/IPv6 rules); a wildcard needs a body with a dot, so `*.com`
  is rejected; a bare label is only allowed for exact `localhost` (so `intranet`, `*.localhost` are
  rejected). Ports, trailing dots and brackets are rejected (they fail the label check).
- **`path_pattern`** (`valid_path_pattern`): either exactly `*`, or a pattern whose body (the pattern
  without an optional single trailing `*`) satisfies all of: starts with `/`; contains no `*`, `?`, `#`;
  every `%` is followed by two **upper-case** hex digits; `normalize_path(body) == body` (already
  normalized: no `.`/`..` segments, no `//`, no escapes of unreserved characters such as `%41`);
  and it is not *self-widening* (section 6.5).
- **`methods`**: each entry non-empty and ASCII alphabetic (`GE T`, `PO\r\nST`, empty strings rejected).
  Entries are upper-cased; any alphabetic word is accepted, not only standard methods.
- **`target_name`**:
  - `header`: a valid HTTP header name (`http::HeaderName`), not one of `host`, `content-length`,
    `transfer-encoding`, `connection`, `keep-alive`, `te`, `trailer`, `upgrade`, and not starting with
    `proxy-` (case-insensitive).
  - `query`: non-empty, only `[A-Za-z0-9_.-]`.
- **`template`**: must contain `{secret}`; no CR, LF or NUL; for `query` it must be exactly `{secret}`.
- **`role`** must exist (`unknown role`), **`secret_id`** must exist (`unknown secret`).

There is no rule update, only add and remove (`remove_rule`); there is no uniqueness constraint. Rule
ids are autoincrement and used as the final tie-break.

### 2.2 Injection kinds and templates

`sg_policy::render(template, secret, kind)` and `crates/proxy/src/inject.rs` (`apply`):

- **Header**: every `{secret}` in the template is replaced by the secret as is (for example
  `Bearer {secret}` or `Basic {secret}`). The proxy removes **every** value the agent sent under that
  header name (case-insensitive) and inserts the rendered value (marked sensitive).
- **Query**: the secret is percent-encoded with `NON_ALPHANUMERIC` (everything except ASCII letters and
  digits is encoded, so `a b&c` becomes `a%20b%26c`). The proxy removes every parameter whose
  percent-decoded name equals `target_name` ASCII-case-insensitively (including a bare `name` with no `=`),
  keeps the other parameters in order, drops empty `&&` fragments, and appends `target_name=<encoded>` at
  the end.
- A rendered value containing CR, LF or NUL is rejected (`invalid injection value`, `502`). A secret
  containing `{secret}` is not expanded twice.
- Independent of rules, the proxy strips from the forwarded request all hop-by-hop headers, every
  `Proxy-*` header, and headers named in `Connection`; the same on the response (`strip_hop_by_hop`).

## 3. Host matching and normalization

`normalize_host(input)` (`normalize.rs`) is applied to the CONNECT target and to every `Host` header and
URI authority:

1. Trim whitespace.
2. `[addr]` or `[addr]:port` gives `addr` (the port, if present, must be digits). Otherwise, if the string has exactly
   one `:`, everything from the colon on is discarded (the port is not validated in that branch); strings with
   more than one `:` are kept whole and must then be an IP literal.
3. Remove **all** trailing dots, lower-case.
4. Accept only 1 to 253 bytes of `[A-Za-z0-9.-_:]`, and a colon only if the result parses as an IP.
   Non-ASCII (for example `münchen.de`), `@`, spaces, CR/LF, NUL give `None`; the proxy answers `400`
   for a bad CONNECT host and `421` for a bad `Host` header. There is no IDN conversion: use punycode.

The port is never part of matching: a rule for `api.example.com` applies to every port the agent
CONNECTs to.

`host_matches(pattern, host)`:

- Exact: `pattern == host`.
- Wildcard `*.suffix`: the host must end in `.suffix` and the part before it must be **exactly one
  non-empty label**. So `*.example.com` matches `api.example.com` but not `example.com`, not
  `a.b.example.com`, not `evilexample.com`, not `api.example.com.evil.com`, not `.example.com`
  (tests `wildcard_host_matches_exactly_one_label`, `wildcard_does_not_match_apex_or_lookalike_suffix`).

Since IP literals cannot have rules, a CONNECT to an IP address always follows the `Unmatched` policy.

## 4. Evaluation, specificity and method semantics

`evaluate(rules, host, method, path)` (`matcher.rs`) returns one of:

- `NoRuleForHost`: no rule's host matches. (In a MITM tunnel the proxy answers `403`.)
- `Forbidden`: the host has rules but no rule authorises this request. (`403`.)
- `Inject(rules)`: the rules to apply, sorted by id.

`path` must already be normalized: the proxy passes `normalize_path(uri.path())`.

Algorithm, in order:

1. **Candidates**: rules of the role whose host matches and whose path matches (`*` always; otherwise
   section 6). **Methods are not considered yet.**
2. **Group** candidates by `(injection kind, target_name lower-cased)`. Each group is one *destination*:
   for example header `Authorization`, or query `api_key`. A header and a query with the same name are
   different groups.
3. In each group, compute each candidate's **specificity**, a tuple compared left to right
   (`specificity`): (a) exact host (`true` beats wildcard); (b) for wildcard hosts, the length of the
   pattern, so `*.prod.corp.com` beats `*.corp.com`; (c) path is exact, i.e. does not end in `*`; (d) length
   of the path pattern. Take the maximum.
4. Among the candidates with exactly that maximum specificity, keep those whose method list is empty
   or contains the request method (ASCII case-insensitive), and pick the one with the **lowest id**.
5. If a group has no such rule, it contributes nothing. It does **not** fall back to a less specific
   rule.
6. If no group contributes, the result is `Forbidden`. Otherwise `Inject` with one rule per contributing
   group, sorted by id.

### Fail-closed method case: worked examples

Rules (host `a.com`, header `A`):

| id | path | methods |
|---|---|---|
| 1 | `/repos/*` | `GET` |
| 2 | `*` | any |

| Request | Candidates | Top specificity | Method filter | Result |
|---|---|---|---|---|
| `GET /repos/x` | 1, 2 | rule 1 (longer path) | GET allowed | inject rule 1 |
| `POST /repos/x` | 1, 2 | rule 1 | POST not in `[GET]` | **`Forbidden`** (rule 2 does not rescue it) |
| `POST /other` | 2 only | rule 2 | any | inject rule 2 |

(test `narrower_rule_is_not_shadowed_by_broader_rule_for_excluded_method`.) This is the guarantee "a
narrower rule is never shadowed by a broader one": restricting `/repos/*` to `GET` really forbids `POST`
there, even though a catch-all rule exists. The guarantee is **per destination**: a rule for a different
header or query parameter is a different group and can still contribute.

Same specificity, different methods coexist: with `/x/*` `GET` (id 1) and `/x/*` `POST` (id 2), `GET`
picks 1, `POST` picks 2, `PUT` is `Forbidden` (test `same_specificity_rules_with_different_methods_coexist`).
Identical specificity and methods: lowest id wins (test `identical_specificity_keeps_first_rule`).

Other asserted examples: an exact host rule beats a wildcard rule even when the wildcard has a longer
path (`exact_host_beats_wildcard_even_with_shorter_path`); `/ab` (exact) beats `/a*` (prefix) for
`/ab`, while `/ac` uses `/a*`; `*.x.com` and `api.x.com` rules for **different** headers both apply.

**Operator note:** a `*` rule for the same destination on the same host is a candidate for every path,
including paths that a restricted rule refuses to judge (section 7). If you want a path restriction to be
the only way to get the credential, do not also create a `*` rule for the same header or parameter on
that host (test `star_pattern_still_matches_unjudgeable_paths`).

## 5. What the proxy does with the decision

Per request (`forward.rs`): host consistency check; `normalize_path`; `list_rules` (fresh from the DB);
`evaluate`; for `Inject`, decrypt each matched rule's secret, render, strip the agent's value for the same
destination, set the injection, forward the **normalized path** and the original query (minus replaced
parameters). `Forbidden` and `NoRuleForHost` both return `403 "not allowed for this role"` and audit
`forbidden`. The audit row records the id of the lowest-id matching rule only.

## 6. Path judging

A rule with `path_pattern = *` matches every path and involves none of this section. For any other pattern,
the rules below apply.

### 6.1 `normalize_path`

`normalize_path(raw)` resolves what is safe to resolve; the proxy forwards its output.

- Split on `/`. For each segment, decode `%XX` escapes **only when they encode an unreserved character**
  (ASCII letter, digit, `-`, `.`, `_`, `~`); hex digits may be any case. Other escapes are left untouched
  (their hex case is kept: `%2f` stays `%2f`), so an encoded `/` stays a literal part of one segment.
- Drop empty segments and `.` segments; `..` removes the previous segment (it cannot go above the root).
- Join with `/`, prefix `/`, and keep a trailing `/` if the input ended with one (and the result is not `/`).
- Not touched: `;` parameters, `\`, the query (the query is not part of the path argument).

Examples asserted in tests: `/repos/../admin` gives `/admin`; `/repos/%2e%2e/admin` gives `/admin`;
`//repos///x` gives `/repos/x`; `/a%2Fb` stays `/a%2Fb`; `/%41pi` gives `/Api`; `/repos/%2e%2e%2f..`
gives `/repos/..%2f..`; `` (empty) gives `/`; the function is idempotent.

Consequence: simple traversals are resolved *before* judging, so `GET /repos/a/../b` is judged and forwarded
as `/repos/b` and is accepted by `/repos/*`; `GET /repos/../admin` becomes `/admin` and is refused.
What you authorise is what is sent.

### 6.2 The readings

Matching a restricted rule does **not** use the normalized path directly: it builds `judge_readings(path)`
(`normalize.rs`), the list `R0, R1, ..., Rn` where `R0` is the normalized path and each next reading is one more round of
percent-decoding, until the string stops changing.

- Round 0 (applied to `R0`) is **strict**: a `%` not followed by two hex digits makes the path unjudgeable.
- Later rounds are lenient about stray `%` (they only see `%` produced by earlier decoding, e.g. `%25`),
  except that `%u` or `%U` anywhere makes the path unjudgeable (the IIS `%uXXXX` form).
- Each round decodes every valid `%HH` to a byte and then requires valid UTF-8 and no NUL.
- If the string is still changing after 8 decoding rounds, the path is unjudgeable.

### 6.3 Dot-like segments and forbidden characters

On **every** reading, the path is refused (unjudgeable) if either holds:

- **A dot-like segment under any separator model.** The reading is split on `/`, `\`, `;`, `?` and `#`
  all at once; a segment is dot-like if it contains a `.` and consists only of `.`, space, tab and `+`.
  Examples: `.`, `..`, `...`, `.. ` (dot dot space), `..+`. So `..;` (splits to `..`), `..\`, `..%2f`
  (reading 1 is `../`), `..%20`, `..+` are all refused.
- **A forbidden character**: any ASCII control character (C0 and DEL, including tab and newline), any
  non-ASCII whitespace, or a code point in the confusable/invisible set `is_forbidden_unicode`:
  U+00A0, U+00AD, U+034F, U+037E, U+1680, U+180E, U+2000 to U+200F, U+2024 to U+2026, U+2028 to U+202F,
  U+2044, U+2047 to U+2049, U+205F to U+2064, U+2215, U+2216, U+29F8, U+3000, U+FE50 to U+FE6B, U+FEFF
  and U+FF01 to U+FF65 (this includes the full-width forms of `.`, `/`, `\`, `?`, `#`, `;`, `%` and others).
  Ordinary non-ASCII text (accented letters, CJK, emoji) is allowed.

### 6.4 Unjudgeable inputs (summary)

For a restricted rule, a path is unjudgeable, the rule does not match, and the result is `Forbidden`
(`403`) when any of these holds (all verified by tests):

| Input | Example |
|---|---|
| Longer than 8192 bytes (8192 is accepted, 8193 is not) | test `oversized_paths_are_forbidden_quickly_and_the_cap_is_inclusive` |
| Malformed `%` in the first round | `/repos/%zz`, `/repos/%` |
| `%u` or `%U` escape | `/repos/%u002e%u002e/admin`, `/repos/%U002E%U002E/admin` |
| NUL | `/repos/a%00b` |
| Other control characters in any reading | `/repos/a%09b`, `/repos/a%0Ab`, `/repos/a%7Fb` |
| Invalid UTF-8 after decoding | `/repos/a%ff` |
| More than 8 decoding layers | (cap `MAX_DECODE_ROUNDS = 8`) |
| Confusable or invisible Unicode | `/repos/%E2%80%A5/admin` (U+2025), `/repos/%EF%BC%8E%EF%BC%8E/admin` (U+FF0E), `/repos/a%E2%80%8Bb` (U+200B), `/repos/..%C2%A0/admin` (U+00A0) |
| A dot-like segment in any reading | `/repos/..%20/admin`, `/repos/.../admin`, `/repos/..;/admin`, `/repos/..%2fadmin`, `/repos/..\admin`, `/repos/..+/admin`, `/repos/..%2B/admin`, `/repos/%252e%252e%252fadmin` |

### 6.5 Prefix and equality semantics

For a restricted pattern, the trailing `*` (if any) marks a **prefix** rule; otherwise the rule is
**exact**. Let `body` be the pattern without the `*`. Matching (`path_matches`):

1. Build the pattern's own readings `P0, P1, ...` by decoding `body` until stable (`pattern_readings`).
2. Let `depths = max(len(readings), len(pattern readings))`. For each depth `d`, compare reading
   `R_min(d, last)` with pattern reading `P_min(d, last)`: the last reading repeats once a chain is exhausted.
3. Prefix rule: **every** depth's request reading must start with the pattern reading at that depth.
   Exact rule: **every** depth must be equal.

Consequences, all consistent with tests:

- `/repos/*` has body `/repos/`: `/repos/` matches; `/repos` and `/reposx` do not (the slash boundary is part of the
  prefix). A prefix not ending in `/` (for example `/v1*`) also matches `/v1beta`, by design.
- `/v1/me` is exact: `/v1/me` matches; `/v1/me/x` and `/v1/me/` do not.
- An encoded `/` is accepted as part of a segment while the request stays inside the prefix:
  `GET /api/v4/projects/a%2Fb/issues` matches `/api/v4/*` and is forwarded unchanged (the GitLab case,
  test `gitlab_style_encoded_project_path_still_injects`).
- `/*` is not the same as `*`: `/*` is a prefix rule with body `/`, and is subject to judging
  (unjudgeable paths do not match it); `*` matches everything without judging.
- Pattern path values must be stored in normalized form (upper-case hex in escapes). `/a%2Fb` is valid;
  `/a%2fb`, `/%41pi`, `/a/../b`, `/a//b` are rejected at creation.

### 6.6 Self-widening patterns (rejected at creation)

A pattern body is rejected if, at **any** decoding depth, it contains `;`, `\`, `?`, `#`, NUL or any
control character, a forbidden Unicode character, a dot-like segment (under any separator model), or
a segment ending in `.` or a space (an origin that trims those, for example a Windows-style one, would
reinterpret the prefix); or if it cannot be decoded safely or exceeds 8192 bytes. Tests list rejected
examples such as `/a%3Bx`, `/a%255Cb`, `/a/%2e%2e/b/*`, `/a/.../b`, `/a/%20../b`, `/v1./*`, `/a /*`, `/v1.`,
`/a%20/*`, `/a%2E/*`, and accepted ones such as `/`, `/*`, `/repos/*`, `/v1/me`, `/a%2Fb`, `/a%2Fb/*`,
`/repos/`, `/api/v4/projects/a%2Fb`, `/api/v4/*`, `/repos/caf%C3%A9/*`, `/v1*`, `/repos/.github/*`, `/a.b/*`.

## 7. The closure argument and its assumptions

The goal: a prefix rule like `/repos/*` must never authorise a request that the origin server
interprets as outside `/repos/`. Origins differ in how they decode, strip `;params`, cut at `?`/`#`,
treat `\` and resolve dots, in unknown order. Instead of modelling one origin, the proxy removes the
thing they would all disagree about:

1. `normalize_path` resolves the plain `.`/`..` segments and the proxy forwards the result.
2. `judge_readings` accepts a path only if, in **every** percent-decoding reading, there is **no** dot-like
   segment under **any** separator model (`/ \ ; ? #` simultaneously), and no confusable or control characters.
3. So, whatever operations an origin applies (decode any number of times, strip `;params`, cut at
   `?`/`#`, map `\` to `/`), there is **no dot segment left to resolve**; those operations can only
   split, shorten or reorder segments that are not dot-like, and none can climb out of the prefix.
4. Each reading must also start with the pattern prefix decoded the same number of times, so an origin
   that decodes `n` times sees a path inside the prefix as read at depth `n`.

Assumptions the argument rests on (spec section 6.2, "Suposiciones sobre el origen", A1 to A6; the spec
defines six, not seven):

| | Assumption |
|---|---|
| A1 | The origin percent-decodes only `%HH` with ASCII hex digits, byte by byte, then reads UTF-8, any number of rounds, at any point. |
| A2 | The origin's separators are a subset of `/ \ ; ? #`, and stripping `;params` removes from `;` to the next `/` or the end. |
| A3 | Origins only remove suffixes starting at `?`/`#`, spans from `;` to the next `/`, one `/` of a `//`, and trailing dots/spaces of a segment. |
| A4 | Character transformations are ASCII only (`\` to `/`, ASCII case folding); Unicode normalisation and `+` as space are covered by the forbidden-character list and by the dot-like set. |
| A5 | A dot segment is only recognised if made of dots, spaces, tabs and `+`. |
| A6 | The origin receives exactly the string that was judged: the proxy forwards `normalize_path(raw)`; the query does not take part in routing. |

An origin that violates these (for example one that folds some other Unicode character into `.`) is outside
the guarantee. The guarantee is about **path prefix rules**; it says nothing about what the origin does with
the content of segments that stay inside the prefix.

Exhaustive test. `crates/policy/src/matcher.rs` contains an independent oracle (it shares no code with the
matcher) that applies every sequence of up to five origin operations to a path and checks that anything the
matcher authorises never resolves outside `/repos/`. The quick variant (token length 3, about 5 thousand
paths) runs in the normal suite; the full variant (token length 5, about 1.5 million paths) is `#[ignore]`d:

```
cargo test -p sg-policy --release -- --include-ignored
```

Run it after any change to `normalize.rs` or `matcher.rs` (it is part of the `/ship` stage in the project workflow).

## 8. Fail-closed side effects operators should know

Because unjudgeable inputs are refused for restricted rules (a `*` rule is unaffected), some legitimate requests get `403`:

- Any request path with a literal `%` that is not a valid escape (for example an unescaped `100%`). Escaped
  `%25` is fine.
- Percent-encoded bytes that are not valid UTF-8 (for example `%ff`), such as binary identifiers in a path.
- Paths containing control characters, NBSP, zero-width characters, or full-width/look-alike punctuation
  in any decoded reading; raw non-ASCII letters, CJK and emoji are fine.
- Segments made only of dots, spaces, tabs and `+` that survive normalization (`...`, `..+`), and `;` forms such as `..;`.
- Paths longer than 8 KiB or encoded more than 8 levels deep.
- Doubly encoded input whose inner reading is dangerous (`%252e%252e%252f`). Plain double-encoding of harmless
  text (such as `%2520` for a space) is still accepted.
- A catch-all `*` rule for the same destination silently covers all of the above (section 4, operator note).
- Rule patterns must be in normalized form with upper-case hex; creation fails otherwise.
- The agent's path is **rewritten** before forwarding: `//`, `.`, `..`, and escapes of unreserved characters
  (`%41` becomes `A`) are normalized. Servers that treat `/a//b` and `/a/b` differently will see the latter.
- The audit log records the raw path (query stripped), not the normalized path.
- Rule changes take effect immediately, including for open tunnels (rules are reloaded per request).
- `Unmatched = passthrough` is decided at CONNECT per host; once a host has any rule, requests in that tunnel
  that match no rule are refused.

## 9. Example requests against `GET /repos/*`

Rule: host `api.github.com` (tests use `api.example.test`), `path_pattern = /repos/*`, `methods = [GET]`,
header `Authorization`, template `Bearer {secret}`. "Forwarded" is the path seen by the upstream. Sources:
`matcher.rs` tests (`method_and_path_restrict`, `every_decoding_depth_and_parsing_variant_is_judged`,
`unicode_separator_lookalikes_and_plus_as_space_are_forbidden`, `closed_by_construction_regressions_are_forbidden`)
and `crates/proxy/tests/inject.rs` (`path_traversal_cannot_escape_a_restricted_rule`,
`witness_that_normalizes_into_the_prefix_is_forwarded_normalized`,
`restricted_rule_still_authorises_legitimate_encoded_paths`).

| Request | Decision | Notes |
|---|---|---|
| `GET /repos/ok`, `GET /repos/x` | inject | |
| `POST /repos/x` | 403 | method excluded |
| `GET /admin`, `GET /other` | 403 | outside the prefix |
| `GET /repos/a/../b` | inject | forwarded as `/repos/b` |
| `GET /repos/a%2Fb` | inject | forwarded unchanged (`%2F` stays encoded) |
| `GET /repos/a%2Fb/issues`, `/repos/a%20b`, `/repos/100%25`, `/repos/caf%C3%A9`, `/repos/a;b` | inject | |
| `GET /repos/a+b`, `/repos/c++`, `/repos/.github`, `/repos/%E6%97%A5%E6%9C%AC`, `/repos/%F0%9F%98%80` | inject | not dot-like, no forbidden characters |
| `GET /repos/a\b` (raw backslash) | inject | forwarded as `/repos/a\b` |
| `GET /repos/a\..%3B\k/../admin` | inject | the plain `..` is resolved first; forwarded as `/repos/admin` |
| `GET /repos/../admin`, `/repos/%2e%2e/admin`, `/repos/%2E%2E/admin` | 403 | normalized to `/admin` |
| `GET /repos/..%2fadmin`, `/repos/..%2Fadmin`, `/repos/%2e%2e%2fadmin`, `/repos/..%5cadmin`, `/repos/..\admin`, `/repos/%2e%2e%5cadmin` | 403 | dot-like segment in a reading |
| `GET /repos/..;/admin`, `/repos/%2e%2e;x/admin`, `/repos/..;%2Frepos%2Fx/..;/admin` | 403 | `;` as separator |
| `GET /repos/%252e%252e%252fadmin`, `/repos/..%252fadmin` | 403 | double encoding |
| `GET /repos/..%20/admin`, `/repos/.../admin`, `/repos/..+/admin`, `/repos/..%2B/admin` | 403 | dot-like segments |
| `GET /repos/%u002e%u002e/admin`, `/repos/%U002E%U002E/admin` | 403 | `%u` escapes |
| `GET /repos/%zz`, `/repos/%`, `/repos/a%ff` | 403 | malformed `%` / invalid UTF-8 |
| `GET /repos/a%00b`, `/repos/a%09b`, `/repos/a%0Ab`, `/repos/a%7Fb` | 403 | control characters |
| `GET /repos/%E2%80%A5/admin`, `/repos/%EF%BC%8E%EF%BC%8E/admin`, raw U+2025, raw U+FF0E, raw U+200B, raw U+00A0 | 403 | confusables / invisibles |
| `GET /repos` or `GET /reposx` (rule `/repos/*`, any method) | 403 | slash boundary |
| `GET /repos/` (same rule) | inject | |
| `GET /repos/` + 8185 `a` (total 8192 bytes) / one more `a` (8193) | inject / 403 | length cap (`/repos/*`, any method) |

## 10. Writing rules

Principles:

1. One secret per destination; one rule per (host, path prefix, methods) you want to allow. Everything else
   on a host that has rules is refused (`403`), so list what the role may do.
2. Use `GET`-only rules for read-only roles; remember the fail-closed method behaviour (section 4).
3. Prefer path prefixes that end in `/*` and start with the API's fixed root; avoid `*` unless the whole host is
   intended.
4. Do not add a second `*` rule for the same destination on the same host unless you want it to cover everything.
5. The CA must permit the host (`CaService::allow_domain`, see [tokens-and-ca.md](tokens-and-ca.md)); otherwise the
   CONNECT for a ruled host answers `502`.
6. Hosts are exact or one-label wildcards; add separate rules for each hostname (for example `api.github.com`
   and `uploads.github.com` are different hosts).

Examples, as `NewRule` JSON (the shape the planned admin API would take; secret ids refer to
secrets created beforehand with `Vault::add_secret`):

GitHub, read-only role and read-write role (`Authorization: Bearer <token>`):

```json
{"role":"reviewer","host_pattern":"api.github.com","path_pattern":"/repos/*","methods":["GET"],
 "kind":"header","target_name":"Authorization","template":"Bearer {secret}","secret_id":1}
```

```json
{"role":"developer","host_pattern":"api.github.com","path_pattern":"*","methods":[],
 "kind":"header","target_name":"Authorization","template":"Bearer {secret}","secret_id":1}
```

GitLab (project paths contain `%2F`; header `PRIVATE-TOKEN`; this mirrors the test
`gitlab_style_encoded_project_path_still_injects`):

```json
{"role":"developer","host_pattern":"gitlab.com","path_pattern":"/api/v4/projects/*","methods":["GET"],
 "kind":"header","target_name":"PRIVATE-TOKEN","template":"{secret}","secret_id":2}
```

Query-style API key:

```json
{"role":"developer","host_pattern":"api.example.com","kind":"query","target_name":"api_key",
 "template":"{secret}","secret_id":3}
```

(`path_pattern` defaults to `*`, `methods` to any.)
