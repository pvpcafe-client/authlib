/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.application.impl;

import cat.psychward.authlib.application.CredentialSource;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.flow.steps.oauth2.HTTPServerAuthStep;

import java.util.Objects;
import java.util.Optional;

public final class OAuthCredentialSource implements CredentialSource {
    private final int port;
    private final String clientId;
    private final Optional<String> clientSecret;

    public OAuthCredentialSource(
            int port,
            String clientId,
            Optional<String> clientSecret
    ) {
        this.port = port;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    public OAuthCredentialSource(int port, String clientId) {
        this(port, clientId, Optional.empty());
    }

    public OAuthCredentialSource(int port, String clientId, String clientSecret) {
        this(port, clientId, Optional.of(clientSecret));
    }

    public int port() {
        return port;
    }

    public String clientId() {
        return clientId;
    }

    public Optional<String> clientSecret() {
        return clientSecret;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        OAuthCredentialSource that = (OAuthCredentialSource) obj;
        return this.port == that.port &&
                Objects.equals(this.clientId, that.clientId) &&
                Objects.equals(this.clientSecret, that.clientSecret);
    }

    @Override
    public int hashCode() {
        return Objects.hash(port, clientId, clientSecret);
    }

    @Override
    public String toString() {
        return "OAuthCredentialSource{" +
                "port=" + port +
                ", clientId='" + clientId + '\'' +
                ", clientSecret=" + clientSecret +
                '}';
    }

    @Override
    public MicrosoftAuthStep initiate() {
        return new HTTPServerAuthStep(this);
    }

    public String buildUrl() {
        return String.format("https://login.live.com/oauth20_authorize.srf?client_id=%s&response_type=code&redirect_uri=%s&scope=XboxLive.signin%%20offline_access&state=NOT_NEEDED", clientId, redirectUri());
    }

    public String redirectUri() {
        return "http://localhost:" + port();
    }
}