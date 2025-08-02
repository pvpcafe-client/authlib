/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.flow.steps;

import cat.psychward.authlib.exceptions.AuthenticationException;
import cat.psychward.authlib.result.MicrosoftAuthResult;
import cat.psychward.authlib.application.impl.OAuthCredentialSource;
import cat.psychward.authlib.exceptions.BasicAuthenticationException;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.result.RefreshTokenResult;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;

import java.io.InputStreamReader;
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
            try (final var client = HttpClients.createDefault()) {
                HttpPost post = new HttpPost("https://login.live.com/oauth20_token.srf");

                List<BasicNameValuePair> params = new ArrayList<>();
                params.add(new BasicNameValuePair("client_id", oauth.clientId()));
                oauth.clientSecret().ifPresent(secret -> params.add(new BasicNameValuePair("client_secret", secret)));
                params.add(new BasicNameValuePair("code", code));
                params.add(new BasicNameValuePair("grant_type", "authorization_code"));
                params.add(new BasicNameValuePair("redirect_uri", oauth.redirectUri()));

                post.setEntity(new UrlEncodedFormEntity(params));
                post.setHeader("Content-Type", "application/x-www-form-urlencoded");

                try (final var response = client.execute(post)) {
                    final var json = JsonParser.parseReader(new InputStreamReader(response.getEntity().getContent()));
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
                }

                throw new BasicAuthenticationException("Failed to get access and refresh token from oauth!");
            }
        } catch (final Exception exception) {
            throw new BasicAuthenticationException(exception);
        }
    }
}