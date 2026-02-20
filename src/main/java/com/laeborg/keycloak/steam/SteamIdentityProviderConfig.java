package com.laeborg.keycloak.steam;

import org.keycloak.models.IdentityProviderModel;

/**
 * Configuration for the Steam OpenID 2.0 identity provider.
 *
 * <p>Extends {@link IdentityProviderModel} directly. In Keycloak 26.x,
 * {@code OAuth2IdentityProviderConfig} was moved out of the public SPI into the internal
 * {@code keycloak-services} artifact and is no longer available to third-party providers.
 * {@code IdentityProviderModel} provides all the fields that appear in the standard
 * identity-provider configuration page in the Keycloak admin UI (alias, display name,
 * enabled, sync mode, etc.).</p>
 *
 * <p>The only Steam-specific extra field is {@code steamApiKey}, which is optional. When
 * supplied, it enables display-name and avatar fetching via the Steam Web API.</p>
 */
public class SteamIdentityProviderConfig extends IdentityProviderModel {

    private static final String STEAM_API_KEY = "steamApiKey";

    /** No-arg constructor required by {@link SteamIdentityProviderFactory#createConfig()}. */
    public SteamIdentityProviderConfig() {
        super();
    }

    /** Copy-constructor used by {@link SteamIdentityProviderFactory#create(org.keycloak.models.KeycloakSession, IdentityProviderModel)}. */
    public SteamIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }

    /**
     * Returns the Steam Web API key, or {@code null} / blank if not configured.
     * When this is set, the provider fetches the player's display name and avatar
     * via {@code ISteamUser/GetPlayerSummaries}.
     */
    public String getSteamApiKey() {
        return getConfig().get(STEAM_API_KEY);
    }

    public void setSteamApiKey(String apiKey) {
        getConfig().put(STEAM_API_KEY, apiKey);
    }
}
