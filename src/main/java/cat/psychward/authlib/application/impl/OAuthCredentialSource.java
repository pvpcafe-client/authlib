/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.application.impl;

import cat.psychward.authlib.application.CredentialSource;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.flow.steps.oauth2.HTTPServerAuthStep;

import java.util.Optional;

public record OAuthCredentialSource(
        int port,
        String clientId,
        Optional<String> clientSecret
) implements CredentialSource {

    public OAuthCredentialSource(int port, String clientId) {
        this(port, clientId, Optional.empty());
    }

    public OAuthCredentialSource(int port, String clientId, String clientSecret) {
        this(port, clientId, Optional.of(clientSecret));
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