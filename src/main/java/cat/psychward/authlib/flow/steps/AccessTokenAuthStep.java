/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.flow.steps;

import cat.psychward.authlib.exceptions.AuthenticationException;
import cat.psychward.http.request.HttpRequest;
import cat.psychward.http.request.impl.FormRequestBody;
import cat.psychward.http.response.impl.JsonResponseBody;
import cat.psychward.authlib.result.MicrosoftAuthResult;
import cat.psychward.authlib.application.impl.OAuthCredentialSource;
import cat.psychward.authlib.exceptions.BasicAuthenticationException;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.result.RefreshTokenResult;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;

public final class AccessTokenAuthStep extends MicrosoftAuthStep {

    private final OAuthCredentialSource oauth;
    private final String code;

    public AccessTokenAuthStep(OAuthCredentialSource oauth, String code) {
        this.oauth = oauth;
        this.code = code;
    }

    @Override
    public MicrosoftAuthResult login() throws AuthenticationException {
        try {

            final List<FormRequestBody.Parameter> parameters = new ArrayList<>();
            parameters.add(new FormRequestBody.Parameter("client_id", oauth.clientId()));
            oauth.clientSecret().ifPresent(secret -> parameters.add(new FormRequestBody.Parameter("client_secret", secret)));
            parameters.add(new FormRequestBody.Parameter("code", code));
            parameters.add(new FormRequestBody.Parameter("grant_type", "authorization_code"));
            parameters.add(new FormRequestBody.Parameter("redirect_uri", oauth.redirectUri()));

            try (HttpRequest request = HttpRequest.builder("https://login.live.com/oauth20_token.srf")
                    .setHeader("Content-Type", "application/x-www-form-urlencoded")
                    .body(new FormRequestBody(parameters))
                    .method("POST")
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