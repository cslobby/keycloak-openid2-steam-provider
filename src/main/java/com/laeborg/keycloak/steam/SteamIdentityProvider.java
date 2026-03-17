package com.laeborg.keycloak.steam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Keycloak Social Identity Provider for Steam using OpenID 2.0.
 *
 * <h2>Authentication flow</h2>
 * <ol>
 *   <li>{@link #performLogin} redirects the user's browser to Steam's OpenID endpoint
 *       ({@code https://steamcommunity.com/openid/login}) with the appropriate params,
 *       embedding the Keycloak broker state in {@code openid.return_to}.</li>
 *   <li>Steam authenticates the user and redirects back to
 *       {@code /realms/{realm}/broker/steam/endpoint?state=...&openid.*=...}.</li>
 *   <li>{@link SteamEndpoint#authResponse} verifies the assertion by re-posting to
 *       Steam's {@code check_authentication} endpoint (server-side HTTP call).</li>
 *   <li>On success the {@code steamid64} is extracted from {@code openid.claimed_id},
 *       an optional Web API call fetches the display name and avatar, and a
 *       {@link BrokeredIdentityContext} is handed to Keycloak to complete login.</li>
 * </ol>
 *
 * <h2>Why extend AbstractOAuth2IdentityProvider?</h2>
 * <p>Keycloak 26.x runs on Quarkus/RESTEasy Reactive. Sub-resource types for the
 * {@code /broker/{provider}/endpoint} path are registered at {@code kc.sh build} time.
 * Only types discovered in Keycloak's own Jandex index are registered — custom extension
 * classes are not. The one extension point that IS registered is
 * {@link AbstractOAuth2IdentityProvider.Endpoint}. By extending it, our
 * {@link SteamEndpoint} inherits that registration and dispatch works correctly.</p>
 */
public class SteamIdentityProvider
        extends AbstractOAuth2IdentityProvider<SteamIdentityProviderConfig>
        implements SocialIdentityProvider<SteamIdentityProviderConfig> {

    static final String STEAM_OPENID_URL = "https://steamcommunity.com/openid/login";
    static final String OPENID_NS        = "http://specs.openid.net/auth/2.0";
    static final String OPENID_ID_SELECT = "http://specs.openid.net/auth/2.0/identifier_select";

    public SteamIdentityProvider(KeycloakSession session, SteamIdentityProviderConfig config) {
        super(session, config);
    }

    // -------------------------------------------------------------------------
    // AbstractOAuth2IdentityProvider abstract method — Steam has no OAuth scopes
    // -------------------------------------------------------------------------

    @Override
    protected String getDefaultScopes() {
        return "";
    }

    // -------------------------------------------------------------------------
    // performLogin — Step 1: redirect the browser to Steam's OpenID endpoint
    // -------------------------------------------------------------------------

    @Override
    public Response performLogin(AuthenticationRequest request) {
        String encodedState = request.getState().getEncoded();

        // request.getRedirectUri() is the broker callback URL:
        //   {base}/realms/{realm}/broker/steam/endpoint
        // Append ?state= so Steam can pass it back on return.
        String returnTo = request.getRedirectUri()
                + "?state=" + URLEncoder.encode(encodedState, StandardCharsets.UTF_8);

        // openid.realm must be a URL prefix of openid.return_to.
        URI baseUri  = request.getUriInfo().getBaseUri();
        String realm = request.getRealm().getName();
        String realmUrl = baseUri.toString().replaceAll("/+$", "") + "/realms/" + realm;

        String steamUrl = STEAM_OPENID_URL
                + "?openid.ns="         + penc(OPENID_NS)
                + "&openid.mode=checkid_setup"
                + "&openid.return_to="  + penc(returnTo)
                + "&openid.realm="      + penc(realmUrl)
                + "&openid.identity="   + penc(OPENID_ID_SELECT)
                + "&openid.claimed_id=" + penc(OPENID_ID_SELECT);

        return Response.seeOther(URI.create(steamUrl)).build();
    }

    // -------------------------------------------------------------------------
    // callback — Step 2: return the JAX-RS endpoint that handles Steam's reply
    // -------------------------------------------------------------------------

    @Override
    public Object callback(RealmModel realm,
                           UserAuthenticationIdentityProvider.AuthenticationCallback callback,
                           EventBuilder event) {
        return new SteamEndpoint(callback, realm, event, this);
    }

    // -------------------------------------------------------------------------
    // updateBrokeredUser — persist custom attributes on first login and on sync
    // -------------------------------------------------------------------------

    @Override
    public void importNewUser(KeycloakSession session, RealmModel realm,
                              UserModel user, BrokeredIdentityContext context) {
        super.importNewUser(session, realm, user, context);
        applySteamAttributes(user, context);
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm,
                                   UserModel user, BrokeredIdentityContext context) {
        super.updateBrokeredUser(session, realm, user, context);
        applySteamAttributes(user, context);
    }

    private void applySteamAttributes(UserModel user, BrokeredIdentityContext context) {
        logger.infof("applySteamAttributes: steamId=%s, username=%s, contextDataKeys=%s",
                context.getId(), context.getUsername(), context.getContextData().keySet());

        String steamId = context.getId();
        if (steamId != null) user.setSingleAttribute("steam_id", steamId);

        String personaName = context.getUsername();
        if (personaName != null) user.setSingleAttribute("steam_username", personaName);

        String avatar = (String) context.getContextData().get("user.attribute.picture");
        if (avatar != null) user.setSingleAttribute("steam_avatar", avatar);
    }

    // -------------------------------------------------------------------------
    // retrieveToken — Steam does not issue OAuth access tokens
    // -------------------------------------------------------------------------

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    private static String penc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    // =========================================================================
    // SteamEndpoint — handles the GET callback from Steam
    //
    // Extends AbstractOAuth2IdentityProvider.Endpoint so that Quarkus/RESTEasy
    // Reactive recognises this as a valid sub-resource type at kc.sh build time.
    // =========================================================================

    public static class SteamEndpoint extends AbstractOAuth2IdentityProvider.Endpoint {

        private static final Logger LOG = Logger.getLogger(SteamEndpoint.class);

        private static final String STEAM_OPENID_URL = "https://steamcommunity.com/openid/login";
        private static final String STEAM_API_URL    = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/";

        private static final Pattern STEAM_ID_PATTERN =
                Pattern.compile("https?://steamcommunity\\.com/openid/id/(\\d{17,25})");

        private static final ObjectMapper JSON = new ObjectMapper();

        private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        // The provider field in the parent is private; keep a typed reference here.
        private final SteamIdentityProvider steamProvider;

        public SteamEndpoint(UserAuthenticationIdentityProvider.AuthenticationCallback callback,
                             RealmModel realm,
                             EventBuilder event,
                             SteamIdentityProvider provider) {
            super(callback, realm, event, provider);
            this.steamProvider = provider;
        }

        /**
         * Overrides the parent's OAuth2 authResponse to implement Steam OpenID 2.0 verification.
         *
         * <p>The {@code state} parameter is injected by JAX-RS from {@code ?state=} in the URL.
         * All {@code openid.*} parameters are read from the Keycloak session URI context rather
         * than via {@code @QueryParam} injection, because the parent signature does not include
         * them and we must match it exactly.</p>
         *
         * @param state            Keycloak broker state (injected by JAX-RS)
         * @param authorizationCode unused — Steam does not issue OAuth codes
         * @param error            unused — Steam signals failure via {@code openid.mode=cancel}
         * @param errorDescription unused
         */
        @GET
        @Override
        public Response authResponse(
                @QueryParam("state")             String state,
                @QueryParam("code")              String authorizationCode,
                @QueryParam("error")             String error,
                @QueryParam("error_description") String errorDescription) {

            MultivaluedMap<String, String> params =
                    session.getContext().getUri().getQueryParameters();

            String mode             = params.getFirst("openid.mode");
            String ns               = params.getFirst("openid.ns");
            String opEndpoint       = params.getFirst("openid.op_endpoint");
            String claimedId        = params.getFirst("openid.claimed_id");
            String identity         = params.getFirst("openid.identity");
            String returnTo         = params.getFirst("openid.return_to");
            String responseNonce    = params.getFirst("openid.response_nonce");
            String invalidateHandle = params.getFirst("openid.invalidate_handle");
            String assocHandle      = params.getFirst("openid.assoc_handle");
            String signed           = params.getFirst("openid.signed");
            String sig              = params.getFirst("openid.sig");

            // --- Guard: state must be present ----------------------------------
            if (state == null || state.isBlank()) {
                LOG.warn("Steam callback received without a state parameter");
                return callback.error(steamProvider.getConfig(), "Missing state parameter in Steam callback");
            }

            // --- Guard: Steam must have approved (mode == id_res) --------------
            if (!"id_res".equals(mode)) {
                LOG.warnf("Steam returned unexpected openid.mode: %s", mode);
                if ("cancel".equals(mode)) {
                    return callback.cancelled(steamProvider.getConfig());
                }
                return callback.error(steamProvider.getConfig(),
                        "Steam authentication was not approved (openid.mode=" + mode + ")");
            }

            // --- Step 1: server-side verification with Steam -------------------
            try {
                boolean valid = verifyWithSteam(ns, opEndpoint, claimedId, identity,
                        returnTo, responseNonce, invalidateHandle, assocHandle, signed, sig);
                if (!valid) {
                    LOG.warn("Steam check_authentication returned is_valid:false");
                    return callback.error(steamProvider.getConfig(),
                            "Steam check_authentication returned is_valid:false");
                }
            } catch (Exception e) {
                LOG.error("Error contacting Steam check_authentication endpoint", e);
                throw new RuntimeException("Failed to verify Steam OpenID assertion", e);
            }

            // --- Step 2: extract steamid64 from claimed_id ---------------------
            String steamId = extractSteamId(claimedId);
            if (steamId == null) {
                LOG.errorf("Could not extract steamid64 from claimed_id: %s", claimedId);
                return callback.error(steamProvider.getConfig(),
                        "Invalid Steam claimed_id — could not extract steamid64");
            }

            // --- Step 3: recover the Keycloak authentication session -----------
            AuthenticationSessionModel authSession;
            try {
                authSession = callback.getAndVerifyAuthenticationSession(state);
            } catch (Exception e) {
                LOG.warnf("Invalid or expired Keycloak state: %s", state);
                return callback.error(steamProvider.getConfig(), "Invalid or expired authentication session");
            }
            if (authSession == null) {
                LOG.warnf("getAndVerifyAuthenticationSession returned null for state: %s", state);
                return callback.error(steamProvider.getConfig(), "Invalid or expired authentication session");
            }
            session.getContext().setAuthenticationSession(authSession);

            // --- Step 4: build the brokered identity ---------------------------
            BrokeredIdentityContext federatedIdentity =
                    new BrokeredIdentityContext(steamId, steamProvider.getConfig());
            federatedIdentity.setIdp(steamProvider);
            federatedIdentity.setAuthenticationSession(authSession);
            federatedIdentity.setUserAttribute("steamid64", steamId);

            String username = steamId;
            String apiKey = steamProvider.getConfig().getSteamApiKey();
            if (apiKey != null && !apiKey.isBlank()) {
                try {
                    SteamProfile profile = fetchSteamProfile(steamId, apiKey);
                    if (profile != null) {
                        if (profile.personaName() != null && !profile.personaName().isBlank()) {
                            username = profile.personaName();
                        }
                        if (profile.avatarUrl() != null && !profile.avatarUrl().isBlank()) {
                            federatedIdentity.setUserAttribute("picture", profile.avatarUrl());
                        }
                    }
                } catch (Exception e) {
                    LOG.warnf(e, "Could not fetch Steam profile for steamid64=%s — using steamid64 as username", steamId);
                }
            }

            federatedIdentity.setUsername(username);
            return callback.authenticated(federatedIdentity);
        }

        // -------------------------------------------------------------------------
        // Verification helpers
        // -------------------------------------------------------------------------

        private boolean verifyWithSteam(String ns, String opEndpoint, String claimedId,
                                        String identity, String returnTo, String responseNonce,
                                        String invalidateHandle, String assocHandle,
                                        String signed, String sig)
                throws IOException, InterruptedException {

            StringBuilder body = new StringBuilder();
            appendFormParam(body, "openid.mode", "check_authentication");
            if (ns              != null) appendFormParam(body, "openid.ns",               ns);
            if (opEndpoint      != null) appendFormParam(body, "openid.op_endpoint",      opEndpoint);
            if (claimedId       != null) appendFormParam(body, "openid.claimed_id",       claimedId);
            if (identity        != null) appendFormParam(body, "openid.identity",         identity);
            if (returnTo        != null) appendFormParam(body, "openid.return_to",        returnTo);
            if (responseNonce   != null) appendFormParam(body, "openid.response_nonce",   responseNonce);
            if (invalidateHandle != null) appendFormParam(body, "openid.invalidate_handle", invalidateHandle);
            if (assocHandle     != null) appendFormParam(body, "openid.assoc_handle",     assocHandle);
            if (signed          != null) appendFormParam(body, "openid.signed",           signed);
            if (sig             != null) appendFormParam(body, "openid.sig",              sig);

            // Strip trailing '&'
            String formBody = body.length() > 0 && body.charAt(body.length() - 1) == '&'
                    ? body.substring(0, body.length() - 1)
                    : body.toString();

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(STEAM_OPENID_URL))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(formBody))
                    .build();

            HttpResponse<String> resp = HTTP_CLIENT.send(req, HttpResponse.BodyHandlers.ofString());
            String responseBody = resp.body();
            return responseBody != null && responseBody.contains("is_valid:true");
        }

        private static void appendFormParam(StringBuilder sb, String key, String value) {
            sb.append(URLEncoder.encode(key,   StandardCharsets.UTF_8))
              .append('=')
              .append(URLEncoder.encode(value, StandardCharsets.UTF_8))
              .append('&');
        }

        private static String extractSteamId(String claimedId) {
            if (claimedId == null) return null;
            Matcher m = STEAM_ID_PATTERN.matcher(claimedId);
            return m.find() ? m.group(1) : null;
        }

        private static SteamProfile fetchSteamProfile(String steamId, String apiKey)
                throws IOException, InterruptedException {

            String url = STEAM_API_URL
                    + "?key="      + URLEncoder.encode(apiKey,  StandardCharsets.UTF_8)
                    + "&steamids=" + URLEncoder.encode(steamId, StandardCharsets.UTF_8);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .build();

            HttpResponse<String> resp = HTTP_CLIENT.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                LOG.warnf("Steam Web API returned HTTP %d for steamid64=%s", resp.statusCode(), steamId);
                return null;
            }

            JsonNode players = JSON.readTree(resp.body())
                                   .path("response")
                                   .path("players");

            if (!players.isArray() || players.isEmpty()) return null;

            JsonNode player = players.get(0);
            return new SteamProfile(
                    player.path("personaname").asText(null),
                    player.path("avatarfull").asText(null));
        }

        record SteamProfile(String personaName, String avatarUrl) {}
    }
}
