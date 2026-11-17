# DRIP authentication

DRIP (IETF Drone Remote ID Protocol) gives aircraft a cryptographic
identity, the DRIP Entity Tag (DET, RFC 9374), and signs Remote ID content
in Authentication messages (RFC 9575). `remoteid` implements the receiver
side and the transmitter side:

| Module | Feature | What |
|---|---|---|
| `drip` | always (`no_std`) | `Det` type, parsing of the four DRIP SAM types, page joining with DRIP FEC, a counter aware page assembler, `paginate` for transmitters |
| `auth` | `verify` | Ed25519 + cSHAKE128 checks (`DripEd25519`), DET to HI binding, Manifest hashes, key stores, the `AuthScheme` trait, `DripSigner` for transmitters |

With `verify` on, the std `Tracker` verifies every complete Authentication
message automatically and the verdict can reach `Authenticated`.

## Formats

| SAM type | Format | Checked |
|---|---|---|
| 0x01 | DRIP Link (Broadcast Endorsement) | parent signature; child DET must hash to the child HI; the child key is learned (trusted only if the parent is) |
| 0x02 | DRIP Wrapper, up to 4 messages | UA signature; signer DET must be a DET the aircraft broadcasts in a Basic ID (no DET Basic ID heard: `unverifiable`); a wrapped Location must equal one received |
| 0x02 | DRIP Wrapper over an extended transport (no evidence) | UA signature over the pack's other messages, rebuilt in message type order |
| 0x03 | DRIP Manifest | UA signature, Current Manifest Hash, and at least one hashed Location (or pack with a Location) matching what was received |
| 0x04 | DRIP Frame | UA signature (no frame types are registered yet, so content is not validated) |

Only HHIT suite 5 (EdDSA / cSHAKE128) is implemented; other suites report
`Unsupported`. Ed25519 checks are strict (RFC 8032 with small order keys and
non canonical signatures rejected).

## Keys and trust

Keys live in a `KeyStore` (`MemoryKeyStore` with std, `FixedKeyStore<N>`
without). Put the keys you trust in it with `trust(det, hi)`: registry or
HDA keys published in DNS (the IETF DRIP registries work describes the
DNS side), or an aircraft's key pinned out of band.

* A Link signed by a trusted parent makes the child key trusted.
* A Link whose parent is unknown still teaches the child key, untrusted.
  The DET is a hash of the key, so signatures under it prove the
  transmitter holds the key of the DET it broadcasts; they do not prove
  who registered it.
* `TrustConfig::accept_self_certified` (default false) decides whether such
  self certified signatures count as `Authenticated`.

## Authentication state

`Assessment::auth` follows the states of RFC 9575 Appendix A: `none`,
`partial` (pages but no complete message), `unsupported`, `unverifiable`
(key missing), `verified` (signature and content check passed),
`trusted` (and the key is trusted), `unverified` (all checked messages
failed), `questionable` (mixed results), `conflicting` (trusted and failed
messages from the same sender).

A Link proves a key, not live data, so only Wrapper, Manifest and Frame
signatures move the state to `verified` or `trusted`. A valid signature
outside its VNB / VNA window (when the receiver has a UTC clock) does not
count and adds the weak reason `auth_expired`.

### Binding to the broadcast identity

A Wrapper, Manifest or Frame counts for an aircraft only when its signer DET
is one of the DETs that aircraft broadcasts in its own Basic ID messages.
This is checked twice: `DripEd25519` returns `SignerNotUas` for another DET
and `Unverifiable` when the aircraft has broadcast no DET yet, and
`TrustState::record_auth` ignores any valid result whose signer is not a
broadcast DET, whatever `AuthScheme` produced it. Without this, a spoofer
could relay a nearby DRIP aircraft's Location and signed Wrapper under its
own serial number and be shown as authenticated.

When an aircraft is verified, `TrustState::authenticated_det()` is the DET
that signed, and `TrackedUas::uas_id()` (the Python `Verdict.uas_id` and
the `aircraft.json` writer use it) shows that DET rather than an unsigned
serial number Basic ID sent beside it.

### Replay and the receiver clock

Without a receiver UTC clock the VNB / VNA window cannot be checked, and a
signed message recorded earlier and replayed elsewhere verifies like a live
one. `TrustConfig::auth_requires_clock` (default true) therefore grants
`Authenticated` only for signatures checked inside their window with
`Observation::unix_ms` set. Without a clock the auth state still reads
`verified` or `trusted`, and the verdict stays `Plausible`. Set it to false
to accept unclocked signatures (for example to replay the RFC example,
whose validity window cannot be checked, see below).

## Bluetooth 4 page assembly

Over Bluetooth 4 every Authentication page is its own frame. RFC 9575
Appendix B sends a whole Manifest as a burst of pages every second while a
Link or Wrapper trickles in at one page per second, with the same auth type
and overlapping page numbers. `drip::AuthAssembler` keeps a burst set
(pages whose counter and page number advance together from page 0, so a
lost frame keeps the burst) and a slow set (everything else, reset at each
page 0 that does not start a burst), closes a burst only at its last page,
and reports each slow message once. One missing page in either set is
rebuilt from the DRIP FEC page. A signature failure on a set that needed
FEC across several seconds is not counted against the aircraft, because
such a set can mix pages of two messages.

## Test vectors and deviations in RFC 9575

`tests/drip.rs` uses the raw example of RFC 9575 Appendix B.2.1 (one DET
and HI, eight ASTM messages, a Link, a Wrapper and a Manifest, all with
FEC). The DET to HI binding, the Wrapper and Manifest signatures, every
Manifest hash and all three FEC pages check out, and were also confirmed
with independent Python code (pycryptodome cSHAKE128, pyca/cryptography
Ed25519). The Link's parent key is not published, so the Link is checked
for structure, FEC and the DET to HI binding only.

The example differs from the RFC text in four places, and the crate
accepts both forms:

1. The Link uses SAM type 0x04 (Frame) instead of 0x01. A Frame whose
   evidence is exactly a DET and an HI is read as a Link (frame type
   0x20, the first DET byte, is unassigned).
2. VNB and VNA count from the Unix epoch, not from 2019-01-01 as Section
   3.2.4.3 requires. The crate uses the 2019 epoch of the text for the
   validity window.
3. The Current Manifest Hash covers the Link hash too, which step 4 of
   Section 4.4.3 leaves out. Either form verifies.
4. The Manifest's Link hash covers the Link's Authentication Data without
   its SAM type byte, not the concatenated pages of Section 4.4.3.1.
   `auth::link_hash` produces the example's form.

The FEC decode check in Figure 12 of the RFC is off by one (it leaves out
the Additional Data Length byte); `drip::assemble` uses the corrected
arithmetic, which the three example messages satisfy. At the time of
writing the RFC Editor lists no errata for RFC 9575.

## National schemes

The Japanese Remote ID scheme authenticates with a message authentication
code whose details are in an MLIT document that was not confirmed while
building 0.2.0, so it is not implemented. It can be added as an
`AuthScheme` without changes elsewhere.
