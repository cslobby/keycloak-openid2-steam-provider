package com.laeborg.keycloak.steam;

import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

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
 *   <li>{@link SteamCallbackEndpoint#authResponse} verifies the assertion by re-posting to
 *       Steam's {@code check_authentication} endpoint (server-side HTTP call).</li>
 *   <li>On success the {@code steamid64} is extracted from {@code openid.claimed_id},
 *       an optional Web API call fetches the display name and avatar, and a
 *       {@link org.keycloak.broker.provider.BrokeredIdentityContext} is handed to
 *       Keycloak to complete login.</li>
 * </ol>
 */
public class SteamIdentityProvider
        extends AbstractIdentityProvider<SteamIdentityProviderConfig>
        implements SocialIdentityProvider<SteamIdentityProviderConfig> {

    private static final Logger LOG = Logger.getLogger(SteamIdentityProvider.class);

    static final String STEAM_OPENID_URL = "https://steamcommunity.com/openid/login";
    static final String OPENID_NS        = "http://specs.openid.net/auth/2.0";
    static final String OPENID_ID_SELECT = "http://specs.openid.net/auth/2.0/identifier_select";

    public SteamIdentityProvider(KeycloakSession session, SteamIdentityProviderConfig config) {
        super(session, config);
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

        LOG.debugf("Redirecting to Steam OpenID: %s", steamUrl);
        return Response.seeOther(URI.create(steamUrl)).build();
    }

    // -------------------------------------------------------------------------
    // callback — Step 2: return the JAX-RS endpoint that handles Steam's reply
    // -------------------------------------------------------------------------

    @Override
    public Object callback(RealmModel realm,
                           UserAuthenticationIdentityProvider.AuthenticationCallback callback,
                           EventBuilder event) {
        LOG.debug("SteamIdentityProvider.callback() called — returning SteamCallbackEndpoint");
        return new SteamCallbackEndpoint(this, callback, realm, event);
    }

    // -------------------------------------------------------------------------
    // retrieveToken — Steam does not issue OAuth access tokens
    // -------------------------------------------------------------------------

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.noContent().build();
    }

    // -------------------------------------------------------------------------
    // Package-private accessor used by SteamCallbackEndpoint
    // -------------------------------------------------------------------------

    /** Returns the request-scoped Keycloak session for this provider instance. */
    KeycloakSession getSession() {
        return session;
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    private static String penc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
