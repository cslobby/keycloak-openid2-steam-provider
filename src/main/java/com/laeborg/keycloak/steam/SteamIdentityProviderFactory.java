package com.laeborg.keycloak.steam;

import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * Factory for the Steam OpenID 2.0 identity provider.
 *
 * <p>Extends {@link AbstractIdentityProviderFactory} to inherit the {@code parseConfig},
 * {@code init}, {@code postInit}, and {@code close} no-op implementations introduced
 * in Keycloak 26.5.x, and implements {@link SocialIdentityProviderFactory} so that
 * Keycloak categorises Steam as a social login provider in the admin UI.</p>
 *
 * <p>Registered via {@code META-INF/services/org.keycloak.broker.provider.IdentityProviderFactory}.
 * Keycloak's ServiceLoader discovers this factory on startup.</p>
 */
public class SteamIdentityProviderFactory
        extends AbstractIdentityProviderFactory<SteamIdentityProvider>
        implements SocialIdentityProviderFactory<SteamIdentityProvider> {

    /** Provider ID — used in URLs ({@code /broker/steam/endpoint}) and admin UI. */
    public static final String PROVIDER_ID = "steam";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /** Display name shown in the "Add identity provider" list in the Keycloak admin UI. */
    @Override
    public String getName() {
        return "Steam";
    }

    @Override
    public SteamIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new SteamIdentityProvider(session, new SteamIdentityProviderConfig(model));
    }

    @Override
    public SteamIdentityProviderConfig createConfig() {
        return new SteamIdentityProviderConfig();
    }

    // parseConfig(KeycloakSession, String), init(), postInit(), and close()
    // are inherited from AbstractIdentityProviderFactory.
}
