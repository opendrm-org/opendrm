# opendrm

Self-hosted DRM. No toll per viewer.

opendrm is a source-available license server, key store and policy engine for
video. You run it on your own servers, keep your own keys, and pay nobody per
device, per license or per customer. It is free for a single organization to
self-host; see [License](#license).

## Status

Phase 1 (license server) works today:

- ClearKey licenses for Chrome, Firefox, Edge and Android
- HLS AES-128 key delivery for Safari and iOS
- Playback tokens signed by your backend (Python SDK:
  [opendrm-python](https://github.com/opendrm-org/opendrm-python))
- Policies: required claims, token age, streams at once, blocked countries
- Hardware-only keys (e.g. 1080p) are never released to software-only systems
- Content keys wrapped with a master key (AES-256-GCM) at rest

Widevine and FairPlay backends come next, once credentials from Google and
Apple arrive. See [docs/architecture.md](docs/architecture.md) and
[docs/getting-drm-credentials.md](docs/getting-drm-credentials.md).

## Try it

```sh
go build -o bin/opendrm ./cmd/opendrm
cp opendrm.example.json opendrm.json
export OPENDRM_TOKEN_SECRET=$(openssl rand -hex 32)

bin/opendrm keys create -title ip-c3 -track sd -policy paid-members
bin/opendrm keys create -title ip-c3 -track 1080p -policy paid-members -hardware
bin/opendrm serve
```

Mint a test token and request a ClearKey license:

```sh
TOKEN=$(bin/opendrm token -user user_1 -title ip-c3 -claim plan=paid)
curl -X POST localhost:8080/v1/license/clearkey \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"kids":["<base64url kid>"],"type":"temporary"}'
```

## Layout

| Path | |
|---|---|
| `cmd/opendrm` | server and CLI |
| `internal/` | key store, tokens, policy, sessions, license endpoints |
| `web/` | Vue console (coming) |
| `docs/` | architecture and credential guides |

## License

The server, console and CLI are under the [Business Source License 1.1](LICENSE):
free to self-host in production for your own organization. Hosting it for
others, running more than one tenant, or offering it as a service needs a
commercial license. Each release becomes Apache-2.0 four years after it ships.

The client SDKs live in their own repositories under
[opendrm-org](https://github.com/opendrm-org) (for example
[opendrm-python](https://github.com/opendrm-org/opendrm-python) and
[opendrm-js](https://github.com/opendrm-org/opendrm-js)). They are Apache-2.0,
so you can embed them anywhere.

Details, including what Enterprise adds, are in [LICENSING.md](LICENSING.md).
