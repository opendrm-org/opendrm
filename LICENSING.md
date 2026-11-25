# Licensing

> DRAFT. This explains the intended model in plain words. The binding terms are
> in [LICENSE](LICENSE). Both must be reviewed by a lawyer before the first
> public release.

openDRM is **source-available**: the code is public, you can read, change and
run it, and it is free for one organization to self-host in production. It is
not "open source" in the OSI sense, because it limits who may host it for
others. Every release becomes Apache-2.0 four years after it ships.

## What is free

You can use the self-hosted server in production, at no cost and with no
per-license, per-device or per-viewer fees, if:

- it protects video that **your organization** owns or may distribute, and
- one deployment serves **one tenant**: your organization.

That includes Widevine, FairPlay, PlayReady, ClearKey and HLS-AES licensing,
packaging, policies, sessions and device limits, signed CDN URLs, the console
with email, password, two-factor and passkey sign-in, fixed roles, a 30-day
security audit log, backups, health checks, webhooks and the API.

Agencies and contractors may install and run openDRM **for a client**, as long
as it runs in the client's own infrastructure and serves only that client.

## What needs a commercial license

- Hosting openDRM for anyone outside your organization.
- Serving more than one tenant from one deployment.
- Offering openDRM, or a service built mainly on it, as a hosted, managed,
  embedded or white-labelled service.
- Enterprise features, unlocked by a signed license file that is checked
  offline (openDRM never phones home):
  - single sign-on (SAML, OIDC), enforced SSO and SCIM provisioning
  - custom roles and fine-grained permissions
  - full audit history, retention beyond 30 days, SIEM and syslog export
  - multiple environments (production, staging, development)
  - multi-tenancy
  - paid modules such as forensic watermarking, GPU transcoding and
    playback analytics
  - support with an SLA and advance security notices

## Ways to buy

| Offer | For |
|---|---|
| **openDRM Cloud** | Teams that want openDRM run for them. Flat plans, no per-license fees. |
| **Enterprise license** | Organizations that self-host and need the features above. |
| **Setup services** | Help getting Widevine, FairPlay and PlayReady credentials and integrating. |

openDRM never charges per license, per play or per device, on any plan.

## SDKs

The SDKs live in their own repositories under
[github.com/opendrm-org](https://github.com/opendrm-org): token SDKs
(`opendrm-python`, `opendrm-js`, `opendrm-go`) and player SDKs
(`opendrm-js`, `opendrm-android`, `opendrm-ios`, `opendrm-flutter`). They are
licensed under the Apache License, Version 2.0, so you can ship them inside
your own apps without restriction.

## Contributing

Contributions require a Contributor License Agreement (CLA), so the project can
keep offering both the free license and commercial licenses. The CLA will be
in place before outside contributions are accepted.

## Trademark

"openDRM" and the openDRM logo are trademarks of Shipscale Software Solutions
Private Limited. Forks may use the code under the license, but must not call
themselves openDRM.

## Licensor

openDRM is owned and licensed by **Shipscale Software Solutions Private
Limited**, an Indian company. Commercial licenses, Enterprise agreements and
openDRM Cloud contracts are signed by this company.

## Open questions before release

- Add the company's CIN and registered office address here, and a licensing
  contact email. Check the exact name against the certificate of incorporation.
- Assign copyright in the existing code from its authors to the company, with a
  board resolution recording that the company owns openDRM.
- Lawyer review of the Additional Use Grant, the Enterprise agreement and the
  CLA.
- Trademark registration for "openDRM".
