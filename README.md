# hut-content-schema

The manifest schema shared between `hut-content` (publishes it) and
`hut-core` (serves puzzle behavior derived from it). Puzzle content is
authored once, by hand, as `manifest/` — a tree of `content.toml` files plus
referenced Markdown/HTML/JSON. Two parsers read the *same* files for two
different purposes, and this directory bundles both of them (plus the small
crypto contract they share) as their own [workspace] (own `Cargo.lock`,
literal dependency versions, no path dependency on anything outside this
repo), so the whole schema/grammar can be checked and tested completely
standalone. It's a submodule of `hut_back`, mounted at `hut-content-schema/`.

- **`manifest/`** — itself a submodule
  ([`hut-27-manifest`](https://github.com/thunt-top/hut-27-manifest), private:
  it's real, live hunt content — puzzle answers and hints, not test data).
  `git submodule update --init --recursive` after cloning to populate it;
  most work here (running either parser's fixture tests, or `cargo check`)
  doesn't need it at all.
- **`behavior_parser/`** (binary + library) — extracts the fields `hut-core`
  needs at runtime (`id`, `title`, `patch`, `answer`) into `behavior.toml` via
  a CLI run during CI (`cargo run -p behavior_parser -- --base manifest --out
  behavior.toml`; see `hut-core/src/behavior.rs`). `hut-core` depends on this
  crate as a library purely to deserialize that file
  (`behavior_parser::BehaviorManifest`), so the schema is defined once and
  shared by both sides rather than duplicated.
- **`content_parser/`** — extracts the resource/grant graph (`base_resource`,
  `contents`, `data`, `hints`, ...) that `hut-content`'s publish pipeline
  builds, encrypts, and uploads. See [Content model](#content-model) below.
  Also ships a CLI (`cargo run -p content_parser -- --base manifest`) that
  runs the same "does this parse and do the grants resolve" check
  `hut-content`'s dry-run mode runs, but against an arbitrary `--base`
  directory and with no `hut-content` (or `.env`) needed at all — see
  [Testing the grammar](#testing-the-grammar).
- **`content_crypto/`** — the key/path derivation (BLAKE3 `derive_key` +
  AES-256-GCM) that both `content_parser` (encrypting at publish time) and
  `hut-core` (deriving/decrypting at request time, see
  `hut-core/src/api/resource.rs`) need identically. A tiny leaf crate with no
  dependency on anything else here, so both sides can take it without pulling
  in the other's concerns.

None of `behavior_parser`/`content_parser`/`content_crypto` has a path
dependency on anything outside this repo (`hut-core`, `hut-content`,
`hut-util`, ...) — the dependency runs the other way: `hut-core` and
`hut-content` each depend inward on whichever leaf crate(s) they need. That's
deliberate: it means the grammar of the hand-written manifest — both the
behavior fields and the content fields — can be fully checked from inside
this repo alone (`cargo test -p behavior_parser -p content_parser`, or
against the real manifest with each crate's `--base` CLI), with nothing else
checked out.

## Content model (`content_parser`)

A puzzle is authored as a `manifest/puzzle/<name>/content.toml` file:

```toml
id = 1
base_resource = 100
title = "Puzzle Title"

[[contents]]
grant = { independent = 101 }
content_file = "body.md"    # or: content = "inline text"

[[data]]
grant = { inherit = 100 }
json = { hint_count = 2 }   # or: json_file = "data.json"

[[hints]]
grant = { purchase = 102 }
title = "First hint"
[hints.answer]
grant = { independent = 103 }
content = "Look under the rug."
```

Every entry (`contents`, `data`, a hint's metadata, a hint's `answer`) has a
`grant`, which controls whether it gets its own encryption key:

- **`independent = <id>`** / **`purchase = <id>`** — the entry is encrypted
  under its own key, derived independently for `<id>`. (`purchase` exists as
  a distinct tag purely so its derived key differs from `independent`'s for
  the same numeric id — the backend decides when a team is actually eligible
  for either.)
- **`inherit = <id>`** — the entry is *not* separately encrypted. Its plain
  JSON value is folded into its parent's encrypted payload, under an
  `"inherit"` map keyed by field name and resource id. A team that can
  decrypt the parent automatically sees everything it inherited.

Resource ids share **one namespace across every grant type**, everywhere in
the manifest. The same numeric id must not be reused as, say, `independent`
in one entry and `purchase` (or `inherit`, or `independent` again) in
another — a resource id names one piece of content, and both the backend's
admin API and this crate's key derivation key purely off of it with no other
disambiguator. `PuzzleScope::build()` enforces this: it panics immediately on
a duplicate resource id, before any content is encrypted or uploaded.

A `hints` entry has a child (its `answer`), and its own content embeds that
child's `(resource_id, version)` once the child has been built — e.g.
`{"title": "...", "answer": {"resource_id": 108, "version": 3}}`. A
`version` only exists once the child's content digest has been filed with the
backend (see [`hut-content`'s publish pipeline](../hut-content/README.md#publish-pipeline)),
so `build()` needs to look versions up as it goes via a
[`VersionRegistry`](#versionregistry-di) rather than being a pure, offline
function of the manifest alone.

### `VersionRegistry` (DI)

```rust
pub trait VersionRegistry {
    async fn version_for(
        &mut self,
        resource_id: ResourceId,
        scope_id: ScopeId,
        digest: blake3::Hash,
    ) -> Result<ResourceRegistration, VersionRegistryError>;
}
```

`content_parser::version_registry` defines the trait plus
`MockVersionRegistry`, an in-memory stand-in that hands out incrementing
version numbers with no network access — used by `content_parser`'s own
integration test and by `hut_content`'s dry-run mode. `hut-content`'s
`src/admin/version_registry.rs` defines the real `AdminVersionRegistry`,
which answers the same lookup via `POST /admin/resource/update` against the
live backend (that endpoint is itself idempotent, so repeated lookups for the
same `(resource_id, scope_id, digest)` always return the same `version`).
`PuzzleScope::build()` and every `ResourceEncrypt::build()` take the registry
as a parameter (generic over `R: VersionRegistry`) rather than constructing
one themselves — `hut-content`'s publish pipeline is what decides which
implementation to inject.

`PuzzleScope::build()` also takes the root `base_key` as a plain `[u8; 32]`
parameter rather than reading `BASE_KEY` itself, for the same reason: the
caller decides where it comes from (the real env var, a fixed constant for
tests, or a random one for a dry run).

`PuzzleScope::build()` walks this graph and returns one `Encrypted` value per
independently-encrypted resource:

```rust
pub struct Encrypted {
    pub encrypted: Vec<u8>,   // gzip'd plaintext, then AES-256-GCM sealed
    pub derive_path: Vec<(&'static str, i32)>, // the (tag, id) chain that produced this resource's key
    pub url_prefix: String,  // this resource's object-path prefix (no version suffix yet)
}
```

## Key and path derivation (`content_crypto`)

Everything is derived from a single root secret, `BASE_KEY` (an env var), via
BLAKE3's keyed `derive_key` mode. A resource's key is the result of folding
`derive_key(parent_key, tag, id)` down the puzzle's grant hierarchy (e.g.
scope → puzzle → resource), so revealing one resource's key never reveals
its siblings' or parent's.

The **encryption key** for a resource and the **object-path prefix**
(`derive_url`) for that same resource are derived from the *same* per-resource
secret, but under separate, hardcoded BLAKE3 contexts (`CTX_KEY` vs.
`CTX_PATH`), so a public object path can never coincide with a key. The
object-path prefix does *not* depend on `version` — only on the resource's
secret and id — because two errata of a resource are logically the same
content, and a team's cached key/URL prefix should keep working across
errata without needing to be re-fetched. The actual object key uploaded to
the bucket is `<prefix>_<version>`, with `version` supplied by the backend at
publish time.

Ciphertext blob layout (served as `application/octet-stream`):

```text
"HU&T"       4 bytes   magic
nonce       12 bytes   random, fresh per encryption
ciphertext   N bytes
tag         16 bytes   AES-GCM tag, appended
```

Content is gzip'd *before* encryption (ciphertext is incompressible, so
compressing after would do nothing).

`hut-core`'s `/resource/get` re-derives a resource's key the same way (see
`hut-core/src/api/resource.rs`) to hand it to an eligible team, without ever
touching the plaintext itself — see
[`hut-content/README.md`](../hut-content/README.md#why-the-content-is-encrypted-client-side)
for why.

## Testing the grammar

Both parsers ship an integration test against a synthetic fixture manifest
committed alongside them (never the real `manifest/` submodule above, which
this repo's own tests don't need populated at all):

- `cargo test -p behavior_parser` — `tests/collect.rs`, walking
  `tests/fixtures/manifest/` and round-tripping the generated
  `behavior.toml`.
- `cargo test -p content_parser` — `tests/build.rs`, building, encrypting,
  re-deriving keys, and decrypting against
  `tests/fixtures/manifest/`.

Both parsers also ship a `--base <dir>` CLI that runs the same checks against
*any* manifest tree, real or not — this is what
[`hut-27-manifest`](https://github.com/thunt-top/hut-27-manifest)'s own CI
runs against the real content on every push (checking out this repo, but not
its `manifest/` submodule — the real content already lives in the repo whose
CI is running):

```bash
cargo run -p behavior_parser -- --base <path-to-manifest> --out /dev/null
cargo run -p content_parser -- --base <path-to-manifest>
```

Since neither crate depends on anything outside this directory, both suites
— i.e. the full grammar check for both the behavior and content sides of a
manifest edit — run from right here with no other part of the workspace
checked out.
