# keycloak-openid2-steam-provider

A Keycloak Social Identity Provider that authenticates users via **Steam's OpenID 2.0** endpoint.
No client ID or client secret is required — Steam's OpenID 2.0 is a verification-based protocol
where Keycloak confirms each assertion server-side by posting back to Steam.

---

## Building

Requirements: JDK 25+, Maven 3.9+.

```bash
mvn package -DskipTests
```

The resulting fat JAR is at:

```
target/keycloak-openid2-steam-provider-1.0.0.jar
```

Because every dependency is `<scope>provided</scope>`, the JAR contains only the compiled
provider classes and the `META-INF/services` descriptor — nothing from the Keycloak runtime
itself is bundled.

---

## Deployment

### Standalone Keycloak

Copy the JAR into the `providers/` directory and restart:

```bash
cp target/keycloak-openid2-steam-provider-1.0.0.jar /opt/keycloak/providers/
/opt/keycloak/bin/kc.sh build   # re-build augmented distribution
/opt/keycloak/bin/kc.sh start
```

### Docker / Kubernetes

Mount the JAR at `/opt/keycloak/providers/` before the `kc.sh start` command runs:

```dockerfile
COPY target/keycloak-openid2-steam-provider-1.0.0.jar /opt/keycloak/providers/
```

Or with a Docker volume / Kubernetes ConfigMap. The Keycloak container will pick it up on
next startup (or after `kc.sh build`).

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

Built against **Keycloak 26.5.x** (`keycloak-server-spi-private` 26.5.3).
If you are running a different patch version, update `<keycloak.version>` in `pom.xml` and
rebuild — no source changes should be needed as long as you stay within the 26.x line.
