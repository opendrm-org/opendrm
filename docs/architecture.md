# opendrm architecture

opendrm is a self-hosted DRM control plane: key store, license server, policy
engine, packager and console. Operators run it on their own servers. Nobody is
billed per device, per license or per customer.

The UI/UX for every surface is designed in Paper:
"opendrm — Design Language & Product UI".

## Stack

| Piece | Language | Notes |
|---|---|---|
| Server: license server, key store, policy, packager, CLI | Go | One static binary (`opendrm`), one Docker image |
| Console and website | Vue.js (TypeScript) | Built to static files, served by the Go binary |
| Playback-token SDK | Python first (`pip install opendrm`), Node next | Used by the operator's backend |
| Players | Shaka (web), Media3 (Android), AVPlayer (iOS), expo-video | Configuration only, no fork |

## Request flow (every play)

```
player ──(license challenge + Bearer playback token)──► opendrm /v1/license/{system}
                                                         │
                                  1. token signature      │  invalid_token
                                  2. token age            │  token_expired
                                  3. entitled to title    │  not_entitled
                                  4. device not revoked   │  device_revoked
                                  5. country              │  geo_blocked
                                  6. security level       │  security_level
                                  7. streams at once      │  concurrency
                                                         ▼
                                  DRM backend wraps the content key
                                  (clearkey · hls-aes now; widevine · fairplay later)
```

Streams are checked last because a granted request takes a stream slot; a
request denied for any other reason must not use one up.

## Packages

| Path | What it does |
|---|---|
| `internal/keystore` | Content keys (16-byte KID + 16-byte AES key). Every key is wrapped with the master key (AES-256-GCM, KID as associated data) before it is stored. |
| `internal/token` | Playback tokens: HS256 JWTs signed by the operator's backend with a shared secret. |
| `internal/policy` | Per-title rules: required claims, token age, stream limit, blocked countries. |
| `internal/session` | Active-stream tracking with a lease (renewed by each license request) and device revocation. |
| `internal/license` | HTTP handlers for each DRM system and the shared authorisation pipeline. |
| `internal/config` | `opendrm.json` loading and defaults. |
| `cmd/opendrm` | CLI: `serve`, `keys`, `token`, `version`. |

Client SDKs live in separate Apache-2.0 repositories under
[opendrm-org](https://github.com/opendrm-org), starting with
[opendrm-python](https://github.com/opendrm-org/opendrm-python)
(`playback_token()` for the operator's backend).

## DRM backends

| System | Status | Covers |
|---|---|---|
| ClearKey (W3C EME) | Phase 1 | Chrome, Firefox, Edge, Android (software protection) |
| HLS AES-128 key delivery | Phase 1 | Safari, iOS (software protection) |
| Widevine | Phase 2, after Google's credentials | Browsers, Android (L1 hardware on most phones) |
| FairPlay | Phase 2, after Apple's credentials | Safari, iOS, Apple TV (hardware) |

Keys marked `requires_hardware` (typically the 1080p track) are never released
to a software-only system. For ClearKey the license simply omits those keys, so
the player restricts itself to the lower renditions.

## Phases

1. **License server (this phase):** key store, tokens, policy, streams,
   ClearKey and HLS-AES endpoints, CLI, Python SDK.
2. **Packaging:** `opendrm package` (CMAF cbcs, HLS + DASH) and the SPEKE v2
   endpoint for AWS MediaConvert.
3. **Widevine and FairPlay backends** once credentials arrive.
4. **Console (Vue)**, persistent license log, admin API, CDN URL signing.
5. Offline licenses, forensic watermarking, leak tracing.
