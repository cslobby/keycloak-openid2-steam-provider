package com.laeborg.keycloak.steam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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
 *   <li>{@link Endpoint#authResponse} verifies the assertion by re-posting to
 *       Steam's {@code check_authentication} endpoint (server-side HTTP call).</li>
 *   <li>On success the {@code steamid64} is extracted from {@code openid.claimed_id},
 *       an optional Web API call fetches the display name and avatar, and a
 *       {@link BrokeredIdentityContext} is handed to Keycloak to complete login.</li>
 * </ol>
 */
public class SteamIdentityProvider
        extends AbstractIdentityProvider<SteamIdentityProviderConfig>
        implements SocialIdentityProvider<SteamIdentityProviderConfig> {

    private static final Logger LOG = Logger.getLogger(SteamIdentityProvider.class);

    static final String STEAM_OPENID_URL  = "https://steamcommunity.com/openid/login";
    static final String STEAM_API_URL     = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/";
    static final String OPENID_NS         = "http://specs.openid.net/auth/2.0";
    static final String OPENID_ID_SELECT  = "http://specs.openid.net/auth/2.0/identifier_select";

    /** Matches the steamid64 at the end of a Steam OpenID claimed_id URL. */
    private static final Pattern STEAM_ID_PATTERN =
            Pattern.compile("https?://steamcommunity\\.com/openid/id/(\\d{17,25})");

    /** Shared ObjectMapper for parsing Steam API JSON responses. */
    private static final ObjectMapper JSON = new ObjectMapper();

    public SteamIdentityProvider(KeycloakSession session, SteamIdentityProviderConfig config) {
        super(session, config);
    }

    // -------------------------------------------------------------------------
    // performLogin — Step 1: redirect the browser to Steam's OpenID endpoint
    // -------------------------------------------------------------------------

    @Override
    public Response performLogin(AuthenticationRequest request) {
        // The encoded Keycloak broker state (carries auth-session reference).
        String encodedState = request.getState().getEncoded();

        // request.getRedirectUri() returns the broker callback URL:
        //   {base}/realms/{realm}/broker/steam/endpoint
        // Append ?state= so that when Steam redirects back Keycloak can
        // recover the authentication session from the state parameter.
        String returnTo = request.getRedirectUri()
                + "?state=" + URLEncoder.encode(encodedState, StandardCharsets.UTF_8);

        // openid.realm must be a URL prefix of openid.return_to.
        // Using the realm's base URL satisfies this requirement.
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

        LOG.debugf("Redirecting to Steam OpenID: %s", steamUrl);
        return Response.seeOther(URI.create(steamUrl)).build();
    }

    // -------------------------------------------------------------------------
    // callback — Step 2: return the JAX-RS endpoint object that handles Steam's
    //            redirect back to Keycloak
    // -------------------------------------------------------------------------

    @Override
    public Object callback(RealmModel realm,
                           UserAuthenticationIdentityProvider.AuthenticationCallback callback,
                           EventBuilder event) {
        LOG.debug("SteamIdentityProvider.callback() called — returning Endpoint");
        return new Endpoint(callback, realm, event);
    }

    // -------------------------------------------------------------------------
    // retrieveToken — Steam does not issue OAuth access tokens
    // -------------------------------------------------------------------------

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.noContent().build();
    }

    // =========================================================================
    // Inner JAX-RS endpoint — handles the callback from Steam
    // =========================================================================

    /**
     * JAX-RS sub-resource returned by {@link #callback}.  Keycloak's
     * {@code IdentityBrokerService} routes GET requests to
     * {@code /realms/{realm}/broker/steam/endpoint} here.
     *
     * <p>Intentionally a non-static inner class so that RESTEasy can inject
     * {@code @Context} fields and properly register it as a sub-resource.</p>
     */
    protected class Endpoint {

        protected final UserAuthenticationIdentityProvider.AuthenticationCallback callback;
        protected final RealmModel realm;
        protected final EventBuilder event;

        @Context
        protected KeycloakSession session;

        public Endpoint(UserAuthenticationIdentityProvider.AuthenticationCallback callback,
                        RealmModel realm,
                        EventBuilder event) {
            this.callback = callback;
            this.realm    = realm;
            this.event    = event;
        }

        /**
         * Handles the GET callback from Steam after the user authenticates.
         *
         * <p>Steam appends all {@code openid.*} parameters to the {@code openid.return_to}
         * URL it received, so they arrive here as query parameters alongside our {@code state}.</p>
         */
        @GET
        public Response authResponse(
                @QueryParam("state")                  String state,
                @QueryParam("openid.mode")            String mode,
                @QueryParam("openid.ns")              String ns,
                @QueryParam("openid.op_endpoint")     String opEndpoint,
                @QueryParam("openid.claimed_id")      String claimedId,
                @QueryParam("openid.identity")        String identity,
                @QueryParam("openid.return_to")       String returnTo,
                @QueryParam("openid.response_nonce")  String responseNonce,
                @QueryParam("openid.invalidate_handle") String invalidateHandle,
                @QueryParam("openid.assoc_handle")    String assocHandle,
                @QueryParam("openid.signed")          String signed,
                @QueryParam("openid.sig")             String sig) {

            LOG.debugf("Endpoint.authResponse() called: state=%s mode=%s claimedId=%s",
                    state, mode, claimedId);

            // --- Guard: state must be present ----------------------------------
            if (state == null || state.isBlank()) {
                LOG.warn("Steam callback received without a state parameter");
                return callback.error(getConfig(), "Missing state parameter in Steam callback");
            }

            // --- Guard: Steam must have approved (mode == id_res) --------------
            if (!"id_res".equals(mode)) {
                LOG.warnf("Steam returned unexpected openid.mode: %s", mode);
                if ("cancel".equals(mode)) {
                    return callback.cancelled(getConfig());
                }
                return callback.error(getConfig(),
                        "Steam authentication was not approved (openid.mode=" + mode + ")");
            }

            // --- Step 1: server-side verification with Steam -------------------
            try {
                boolean valid = verifyWithSteam(ns, opEndpoint, claimedId, identity,
                        returnTo, responseNonce, invalidateHandle, assocHandle, signed, sig);
                if (!valid) {
                    LOG.warn("Steam check_authentication returned is_valid:false");
                    return callback.error(getConfig(),
                            "Steam check_authentication returned is_valid:false — the assertion could not be verified");
                }
            } catch (Exception e) {
                LOG.error("Error contacting Steam check_authentication endpoint", e);
                throw new RuntimeException("Failed to verify Steam OpenID assertion", e);
            }

            // --- Step 2: extract steamid64 from claimed_id ---------------------
            String steamId = extractSteamId(claimedId);
            if (steamId == null) {
                LOG.errorf("Could not extract steamid64 from claimed_id: %s", claimedId);
                return callback.error(getConfig(),
                        "Invalid Steam claimed_id — could not extract steamid64");
            }

            // --- Step 3: recover the Keycloak authentication session -----------
            AuthenticationSessionModel authSession;
            try {
                authSession = callback.getAndVerifyAuthenticationSession(state);
            } catch (Exception e) {
                LOG.warnf("Invalid or expired Keycloak state in Steam callback: %s", state);
                return callback.error(getConfig(), "Invalid or expired authentication session");
            }
            session.getContext().setAuthenticationSession(authSession);

            // --- Step 4: build the brokered identity ---------------------------
            BrokeredIdentityContext federatedIdentity =
                    new BrokeredIdentityContext(steamId, getConfig());
            federatedIdentity.setIdp(SteamIdentityProvider.this);
            federatedIdentity.setAuthenticationSession(authSession);
            federatedIdentity.setUserAttribute("steamid64", steamId);

            // Use steamid64 as the Keycloak username by default; override with
            // the Steam display name when an API key is configured.
            String username = steamId;
            String apiKey = getConfig().getSteamApiKey();
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
                    LOG.warnf(e,
                            "Could not fetch Steam profile for steamid64=%s — falling back to steamid64 as username",
                            steamId);
                }
            }

            federatedIdentity.setUsername(username);

            LOG.debugf("Steam authentication successful: steamid64=%s username=%s", steamId, username);
            return callback.authenticated(federatedIdentity);
        }

        // ---- Verification helpers -------------------------------------------

        /**
         * Re-posts to Steam's {@code check_authentication} endpoint to validate
         * the OpenID assertion server-side.  Returns {@code true} iff Steam
         * responds with {@code is_valid:true}.
         */
        private boolean verifyWithSteam(String ns, String opEndpoint, String claimedId,
                                        String identity, String returnTo, String responseNonce,
                                        String invalidateHandle, String assocHandle,
                                        String signed, String sig)
                throws IOException, InterruptedException {

            StringBuilder body = new StringBuilder();
            // Switch mode to check_authentication; all other params stay the same.
            appendFormParam(body, "openid.mode", "check_authentication");
            if (ns            != null) appendFormParam(body, "openid.ns",               ns);
            if (opEndpoint    != null) appendFormParam(body, "openid.op_endpoint",      opEndpoint);
            if (claimedId     != null) appendFormParam(body, "openid.claimed_id",       claimedId);
            if (identity      != null) appendFormParam(body, "openid.identity",         identity);
            if (returnTo      != null) appendFormParam(body, "openid.return_to",        returnTo);
            if (responseNonce != null) appendFormParam(body, "openid.response_nonce",   responseNonce);
            if (invalidateHandle != null) appendFormParam(body, "openid.invalidate_handle", invalidateHandle);
            if (assocHandle   != null) appendFormParam(body, "openid.assoc_handle",     assocHandle);
            if (signed        != null) appendFormParam(body, "openid.signed",           signed);
            if (sig           != null) appendFormParam(body, "openid.sig",              sig);

            // Strip trailing '&'
            String formBody = body.length() > 0 && body.charAt(body.length() - 1) == '&'
                    ? body.substring(0, body.length() - 1)
                    : body.toString();

            HttpClient client = HttpClient.newHttpClient();
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(STEAM_OPENID_URL))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(formBody))
                    .build();

            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            String responseBody = resp.body();
            LOG.debugf("Steam check_authentication response (status=%d): %s", resp.statusCode(), responseBody);

            return responseBody != null && responseBody.contains("is_valid:true");
        }

        /** Appends a URL-encoded key=value& pair to the given StringBuilder. */
        private static void appendFormParam(StringBuilder sb, String key, String value) {
            sb.append(URLEncoder.encode(key,   StandardCharsets.UTF_8))
              .append('=')
              .append(URLEncoder.encode(value, StandardCharsets.UTF_8))
              .append('&');
        }

        /**
         * Extracts the {@code steamid64} from a Steam OpenID {@code claimed_id} URL of the form
         * {@code https://steamcommunity.com/openid/id/<steamid64>}.
         *
         * @return the steamid64 string, or {@code null} if the URL does not match.
         */
        private static String extractSteamId(String claimedId) {
            if (claimedId == null) return null;
            Matcher m = STEAM_ID_PATTERN.matcher(claimedId);
            return m.find() ? m.group(1) : null;
        }

        /**
         * Calls {@code ISteamUser/GetPlayerSummaries} and returns the player's
         * display name ({@code personaname}) and full-size avatar URL ({@code avatarfull}).
         *
         * @return a {@link SteamProfile} record, or {@code null} if the player was not found.
         */
        private static SteamProfile fetchSteamProfile(String steamId, String apiKey)
                throws IOException, InterruptedException {

            String url = STEAM_API_URL
                    + "?key="      + URLEncoder.encode(apiKey,   StandardCharsets.UTF_8)
                    + "&steamids=" + URLEncoder.encode(steamId, StandardCharsets.UTF_8);

            HttpClient client = HttpClient.newHttpClient();
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .build();

            HttpResponse<String> resp = client.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                LOG.warnf("Steam Web API returned HTTP %d for steamid64=%s", resp.statusCode(), steamId);
                return null;
            }

            JsonNode players = JSON.readTree(resp.body())
                                   .path("response")
                                   .path("players");

            if (!players.isArray() || players.isEmpty()) {
                return null;
            }

            JsonNode player = players.get(0);
            return new SteamProfile(
                    player.path("personaname").asText(null),
                    player.path("avatarfull").asText(null));
        }
    }

    // =========================================================================
    // Utility
    // =========================================================================

    /** URL-encodes a value using UTF-8 (convenience shorthand). */
    private static String penc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** Immutable value object for a Steam player summary. */
    private record SteamProfile(String personaName, String avatarUrl) {}
}
