# keycloak-openid2-steam-provider

A Keycloak Social Identity Provider that authenticates users via **Steam's OpenID 2.0** endpoint.
No client ID or client secret is required — Steam's OpenID 2.0 is a verification-based protocol
where Keycloak confirms each assertion server-side by posting back to Steam.

---

## Building

Requirements: JDK 21+, Maven 3.9+.

```bash
mvn package
```

The resulting fat JAR is at:

```
target/keycloak-openid2-steam-provider-1.0.0.jar
```

Every dependency is `<scope>provided</scope>`, so the JAR contains only the compiled provider
classes, the `META-INF/services` descriptor, and a Jandex index (`META-INF/jandex.idx`).
Nothing from the Keycloak runtime is bundled.

---

## Deployment

> **Important:** After placing the JAR you must run `kc.sh build` to trigger Quarkus
> augmentation. Without this step Keycloak will not dispatch requests to the callback
> endpoint and authentication will fail with an internal server error.

### Standalone Keycloak

```bash
cp target/keycloak-openid2-steam-provider-1.0.0.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build
/opt/keycloak/bin/kc.sh start
```

### Docker / Kubernetes

Include the JAR in your custom image and run `kc.sh build` as part of the image build:

```dockerfile
FROM quay.io/keycloak/keycloak:26.5.3

COPY target/keycloak-openid2-steam-provider-1.0.0.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start"]
```

Running `kc.sh build` at image-build time (rather than at pod startup) is the recommended
pattern for production Kubernetes deployments — the optimised distribution is baked into
the image and pods start faster.

---

## Configuration in the Keycloak Admin UI

1. Open **Identity Providers** in your realm.
2. Click **Add provider** → select **Steam** from the list.
3. Fill in:

| Field | Description |
|---|---|
| **Alias** | URL-safe identifier, e.g. `steam`. Used in the callback URL. |
| **Display name** | Label shown on the login button, e.g. `Steam`. |
| **Steam API Key** | *(Optional)* A key from [steamcommunity.com/dev/apikey](https://steamcommunity.com/dev/apikey). When set, the provider fetches the user's display name and full avatar URL from `ISteamUser/GetPlayerSummaries`. Leave blank to use `steamid64` as the username. |
| Client ID / Client Secret | Leave **blank** — they are not used for Steam OpenID 2.0. |

4. Save. The provider is now active.

> **Tip:** Add a **User Attribute Mapper** in the provider's *Mappers* tab to expose
> `steamid64` (and optionally `picture`) as a token claim.

---

## Authentication Flow

```
Browser                         Keycloak                        Steam
  |                                |                               |
  |-- GET /realms/…/login -------> |                               |
  |                                |                               |
  |<-- 302 → Steam OpenID -------- |                               |
  |                                                                |
  |-- GET steamcommunity.com/openid/login?… --------------------> |
  |                                                                |
  |<-- 302 → /realms/…/broker/steam/endpoint?state=…&openid.*=… - |
  |                                                                |
  |-- GET /realms/…/broker/steam/endpoint?… -----> |              |
  |                                                |              |
  |                                                |-- POST → steamcommunity.com/openid/login
  |                                                |   (check_authentication)           |
  |                                                |<-- is_valid:true ------------------ |
  |                                                |                                    |
  |                           (optional) GET api.steampowered.com/ISteamUser/…          |
  |                                                |                                    |
  |<-- 302 → client app with id_token / code ----- |
```

---

## User Attributes Set

| Attribute | Value | Always set? |
|---|---|---|
| `username` | Steam display name (if API key configured) or `steamid64` | Yes |
| `steamid64` | 17-digit Steam64 ID | Yes |
| `picture` | Full-size avatar URL from Steam Web API | Only when API key is configured |

The `steamid64` attribute can be exposed as a JWT claim via a **User Attribute Mapper**:

- **Mapper Type:** `User Attribute`
- **User Attribute:** `steamid64`
- **Token Claim Name:** `steamid64` (or any name you prefer)

---

## Keycloak Version Compatibility

Built against **Keycloak 26.5.x** (`keycloak-services` 26.5.3).
If you are running a different patch version, update `<keycloak.version>` in `pom.xml` and
rebuild — no source changes should be needed as long as you stay within the 26.x line.

---

## Technical Notes

### Why `AbstractOAuth2IdentityProvider` instead of `AbstractIdentityProvider`?

Keycloak 26.x runs on Quarkus with RESTEasy Reactive. Sub-resource types for the
`/broker/{provider}/endpoint` path are registered at **`kc.sh build` time** via Jandex
scanning. Only types present in Keycloak's own distribution JARs are registered — custom
endpoint classes in extension JARs are not discovered, causing dispatch to silently fail
with HTTP 500.

The fix is to extend `AbstractOAuth2IdentityProvider.Endpoint` (from `keycloak-services`),
which IS registered at build time. Our `SteamEndpoint` inherits that registration and
Quarkus can dispatch to it correctly. The `@GET authResponse()` method is overridden to
implement Steam's OpenID 2.0 verification instead of the standard OAuth2 code exchange.
