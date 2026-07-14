/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.flow.steps;

import cat.psychward.authlib.application.api.ClientCredentialSource;
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
import java.util.function.BiConsumer;

public final class TokenAuthStep extends MicrosoftAuthStep {

    private final ClientCredentialSource source;
    private final String token;
    private final Type type;

    public TokenAuthStep(ClientCredentialSource source, String token, Type type) {
        this.source = source;
        this.token = token;
        this.type = type;
    }

    @Override
    public MicrosoftAuthResult login() throws AuthenticationException {
        try {

            final List<FormRequestBody.Parameter> parameters = new ArrayList<>();
            source.appendParameters(parameters);
            type.consumer.accept(token, parameters);

            try (HttpRequest request = HttpRequest.builder("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
                    .method("POST")
                    .setHeader("Content-Type", "application/x-www-form-urlencoded")
                    .body(new FormRequestBody(parameters))
                    .build()) {
                JsonElement json = request.execute().as(JsonResponseBody.class).getJson();

                if (json.isJsonObject()) {
                    final JsonObject object = json.getAsJsonObject();
                    if (!object.has("refresh_token"))
                        throw new BasicAuthenticationException("Missing 'refresh_token' in response");

                    if (!object.has("access_token"))
                        throw new BasicAuthenticationException("Missing 'access_token' in response");

                    final String accessToken = object.get("access_token").getAsString();
                    final String refreshToken = object.get("refresh_token").getAsString();
                    return new RefreshTokenResult(
                            refreshToken,
                            new XboxAuthStep(source.clientId(), accessToken).login()
                    );
                }

                throw new BasicAuthenticationException("Failed to get access and refresh token from oauth!");
            }
        } catch (final Exception exception) {
            throw new BasicAuthenticationException(exception);
        }
    }

    public enum Type {
        ACCESS_TOKEN((code, parameters) -> {
            parameters.add(new FormRequestBody.Parameter("code", code));
            parameters.add(new FormRequestBody.Parameter("grant_type", "authorization_code"));
        }),
        REFRESH_TOKEN((token, parameters) -> {
            parameters.add(new FormRequestBody.Parameter("refresh_token", token));
            parameters.add(new FormRequestBody.Parameter("grant_type", "refresh_token"));
        });

        final BiConsumer<String, List<FormRequestBody.Parameter>> consumer;

        Type(BiConsumer<String, List<FormRequestBody.Parameter>> consumer) {
            this.consumer = consumer;
        }
    }
}