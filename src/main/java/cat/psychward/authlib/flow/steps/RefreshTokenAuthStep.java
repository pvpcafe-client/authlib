/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.flow.steps;

import cat.psychward.authlib.application.impl.OAuthCredentialSource;
import cat.psychward.authlib.exceptions.AuthenticationException;
import cat.psychward.authlib.exceptions.BasicAuthenticationException;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.http.request.HttpRequest;
import cat.psychward.http.request.impl.FormRequestBody;
import cat.psychward.http.response.impl.JsonResponseBody;
import cat.psychward.authlib.result.MicrosoftAuthResult;
import cat.psychward.authlib.result.RefreshTokenResult;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

public final class RefreshTokenAuthStep extends MicrosoftAuthStep {

    private final OAuthCredentialSource oauth;
    private final String refreshToken;

    public RefreshTokenAuthStep(OAuthCredentialSource oauth, String refreshToken) {
        this.oauth = oauth;
        this.refreshToken = refreshToken;
    }

    @Override
    public MicrosoftAuthResult login() throws AuthenticationException {
        try {

            final List<FormRequestBody.Parameter> parameters = new ArrayList<>();
            parameters.add(new FormRequestBody.Parameter("client_id", oauth.clientId()));
            oauth.clientSecret().ifPresent(secret -> parameters.add(new FormRequestBody.Parameter("client_secret", secret)));
            parameters.add(new FormRequestBody.Parameter("refresh_token", refreshToken));
            parameters.add(new FormRequestBody.Parameter("grant_type", "refresh_token"));
            parameters.add(new FormRequestBody.Parameter("redirect_uri", oauth.redirectUri()));

            try (HttpRequest request = HttpRequest.builder("https://login.live.com/oauth20_token.srf")
                    .method("POST")
                    .setHeader("Content-Type", "application/x-www-form-urlencoded")
                    .body(new FormRequestBody(parameters))
                    .build()) {
                JsonElement json = request.execute().as(JsonResponseBody.class).getJson();

                if (json.isJsonObject()) {
                    final JsonObject object = json.getAsJsonObject();
                    if (object.has("access_token") && object.has("refresh_token")) {
                        final String accessToken = object.get("access_token").getAsString();
                        final String refreshToken = object.get("refresh_token").getAsString();
                        return new RefreshTokenResult(
                                refreshToken,
                                new XboxAuthStep(accessToken).login()
                        );
                    }
                }

                throw new BasicAuthenticationException("Failed to get access and refresh token from oauth!");
            }
        } catch (final Exception exception) {
            throw new BasicAuthenticationException(exception);
        }
    }
}