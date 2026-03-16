package com.laeborg.keycloak.steam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.RealmModel;
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
 * JAX-RS sub-resource returned by {@link SteamIdentityProvider#callback}.
 *
 * <p>Must be a <em>top-level</em> class (not a nested class). RESTEasy Reactive
 * registers potential sub-resource types at Quarkus build time by scanning the
 * Jandex index. Nested classes (whose bytecode names contain {@code $}) are
 * skipped by this scan, so the {@code @GET} method is never registered and
 * dispatch silently fails with a 500.</p>
 */
public class SteamCallbackEndpoint {

    private static final Logger LOG = Logger.getLogger(SteamCallbackEndpoint.class);

    private static final String STEAM_OPENID_URL = "https://steamcommunity.com/openid/login";
    private static final String STEAM_API_URL    = "https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/";

    private static final Pattern STEAM_ID_PATTERN =
            Pattern.compile("https?://steamcommunity\\.com/openid/id/(\\d{17,25})");

    private static final ObjectMapper JSON = new ObjectMapper();

    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    private final SteamIdentityProvider provider;
    private final UserAuthenticationIdentityProvider.AuthenticationCallback callback;
    private final RealmModel realm;
    private final EventBuilder event;

    public SteamCallbackEndpoint(SteamIdentityProvider provider,
                                 UserAuthenticationIdentityProvider.AuthenticationCallback callback,
                                 RealmModel realm,
                                 EventBuilder event) {
        this.provider = provider;
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
            @QueryParam("state")                    String state,
            @QueryParam("openid.mode")              String mode,
            @QueryParam("openid.ns")                String ns,
            @QueryParam("openid.op_endpoint")       String opEndpoint,
            @QueryParam("openid.claimed_id")        String claimedId,
            @QueryParam("openid.identity")          String identity,
            @QueryParam("openid.return_to")         String returnTo,
            @QueryParam("openid.response_nonce")    String responseNonce,
            @QueryParam("openid.invalidate_handle") String invalidateHandle,
            @QueryParam("openid.assoc_handle")      String assocHandle,
            @QueryParam("openid.signed")            String signed,
            @QueryParam("openid.sig")               String sig) {

        LOG.debugf("SteamCallbackEndpoint.authResponse() called: state=%s mode=%s claimedId=%s",
                state, mode, claimedId);

        // --- Guard: state must be present ----------------------------------
        if (state == null || state.isBlank()) {
            LOG.warn("Steam callback received without a state parameter");
            return callback.error(provider.getConfig(), "Missing state parameter in Steam callback");
        }

        // --- Guard: Steam must have approved (mode == id_res) --------------
        if (!"id_res".equals(mode)) {
            LOG.warnf("Steam returned unexpected openid.mode: %s", mode);
            if ("cancel".equals(mode)) {
                return callback.cancelled(provider.getConfig());
            }
            return callback.error(provider.getConfig(),
                    "Steam authentication was not approved (openid.mode=" + mode + ")");
        }

        // --- Step 1: server-side verification with Steam -------------------
        try {
            boolean valid = verifyWithSteam(ns, opEndpoint, claimedId, identity,
                    returnTo, responseNonce, invalidateHandle, assocHandle, signed, sig);
            if (!valid) {
                LOG.warn("Steam check_authentication returned is_valid:false");
                return callback.error(provider.getConfig(),
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
            return callback.error(provider.getConfig(),
                    "Invalid Steam claimed_id — could not extract steamid64");
        }

        // --- Step 3: recover the Keycloak authentication session -----------
        AuthenticationSessionModel authSession;
        try {
            authSession = callback.getAndVerifyAuthenticationSession(state);
        } catch (Exception e) {
            LOG.warnf("Invalid or expired Keycloak state: %s", state);
            return callback.error(provider.getConfig(), "Invalid or expired authentication session");
        }
        if (authSession == null) {
            LOG.warnf("getAndVerifyAuthenticationSession returned null for state: %s", state);
            return callback.error(provider.getConfig(), "Invalid or expired authentication session");
        }
        provider.getSession().getContext().setAuthenticationSession(authSession);

        // --- Step 4: build the brokered identity ---------------------------
        BrokeredIdentityContext federatedIdentity =
                new BrokeredIdentityContext(steamId, provider.getConfig());
        federatedIdentity.setIdp(provider);
        federatedIdentity.setAuthenticationSession(authSession);
        federatedIdentity.setUserAttribute("steamid64", steamId);

        String username = steamId;
        String apiKey = provider.getConfig().getSteamApiKey();
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
        LOG.debugf("Steam authentication successful: steamid64=%s username=%s", steamId, username);
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
        LOG.debugf("Steam check_authentication response (status=%d): %s", resp.statusCode(), responseBody);

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
