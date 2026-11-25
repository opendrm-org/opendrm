# Getting DRM credentials

opendrm is software. It never holds DRM credentials itself: every operator (the
company that runs the streaming service) applies for its own. Apple in particular
only approves the streaming service, not a vendor acting for it.

To reach browsers, Android and iOS you need two:

| DRM | Covers | Cost | Who applies |
|---|---|---|---|
| Widevine | Chrome, Firefox, Edge, Android | No fee; a license agreement with Google is required | Your company |
| FairPlay Streaming | Safari (Mac), every browser on iPhone/iPad, iOS apps | Included in the Apple Developer Program (US$99/yr) | The **Account Holder** of your Apple Developer account |

PlayReady is not needed for these targets.

## FairPlay Streaming

1. Sign in to <https://developer.apple.com/streaming/fps/> as the **Account
   Holder**. Admins and developers see "Your account can't access this page".
2. Request the FairPlay Streaming deployment package. The form asks, among other
   things:
   - whether this is your first FPS credentials request;
   - whether the account holder owns, or is licensed to use, the content;
   - a description of your streaming service.
3. Apple approves only teams that provide a streaming service to consumers.
   Expect a few days; some requests take longer.
4. Once approved, follow Apple's instructions in the package to create:
   - the **FPS certificate** (public, sent to players),
   - the **private key** for that certificate,
   - the **Application Secret key (ASk)**.

   Store the private key and ASk in your secret manager. If you lose them you
   must request again, and every existing license flow breaks.

## Widevine

1. Go to <https://www.widevine.com>, open **Contact**, and choose **General
   Questions** to start a license agreement. (Licensees use **Support**
   instead.) Google's contact page: <https://developers.google.com/widevine/contact/support>.
2. Google issues per-organization credentials, first for the **Test**
   environment, then **Production**. There is no fee.
3. Have ready: legal entity, website, what you stream, platforms, rough
   subscriber and monthly-playback numbers, and whether you will run your own
   license service (opendrm) or a Google-hosted one.
4. Approval for small companies can be slow. Interim option: put one of the
   [Widevine third-party license providers](https://www.widevine.com/solutions/widevine-providers)
   behind opendrm's license API, keep keys and entitlement rules in opendrm, and
   swap the provider out once your own credentials arrive.

## Until credentials arrive

opendrm's software-only backends need no agreements:

- **ClearKey** for Chrome, Firefox, Edge and Android, using the same CBCS files
  that Widevine will use later.
- **AES-128 HLS** for Safari and iOS, with keys served behind session tokens.

These stop casual downloading and link sharing, not a determined attacker.
Combine them with signed CDN URLs, concurrency limits and watermarking.
