/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.flow.steps.oauth2;

import cat.psychward.authlib.application.impl.DeviceCodeCredentialSource;
import cat.psychward.authlib.exceptions.AuthenticationException;
import cat.psychward.authlib.exceptions.BasicAuthenticationException;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.flow.steps.XboxAuthStep;
import cat.psychward.authlib.result.MicrosoftAuthResult;
import cat.psychward.authlib.result.RefreshTokenResult;
import cat.psychward.http.request.HttpRequest;
import cat.psychward.http.request.impl.FormRequestBody;
import cat.psychward.http.response.impl.JsonResponseBody;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public final class DeviceCodeAuthStep extends MicrosoftAuthStep {

    private final DeviceCodeCredentialSource code;

    public DeviceCodeAuthStep(DeviceCodeCredentialSource code) {
        this.code = code;
    }

    @Override
    public MicrosoftAuthResult login() throws AuthenticationException {
        final List<FormRequestBody.Parameter> parameters = new ArrayList<>();
        parameters.add(new FormRequestBody.Parameter("client_id", code.clientId()));
        parameters.add(new FormRequestBody.Parameter("scope", "XboxLive.signin offline_access"));

        try (HttpRequest request = HttpRequest.builder("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode")
                .method("POST")
                .body(new FormRequestBody(parameters))
                .build()) {

            final JsonElement deviceCodeJson = request.execute().as(JsonResponseBody.class).getJson();
            if (!deviceCodeJson.isJsonObject())
                throw new BasicAuthenticationException("Invalid response from device code endpoint.");

            JsonObject deviceCodeObject = deviceCodeJson.getAsJsonObject();

            if (!deviceCodeObject.has("device_code") || !deviceCodeObject.has("user_code") ||
                    !deviceCodeObject.has("interval") || !deviceCodeObject.has("expires_in"))
                throw new BasicAuthenticationException("Failed to retrieve device code: " + deviceCodeJson);

            final String deviceCode = deviceCodeObject.get("device_code").getAsString(),
                    userCode = deviceCodeObject.get("user_code").getAsString();

            int interval = deviceCodeObject.get("interval").getAsInt(),
                    expiresIn = deviceCodeObject.get("expires_in").getAsInt();

            code.deviceCodeConsumer().accept(
                    deviceCodeObject.get("verification_uri").getAsString(),
                    userCode
            );

            final long startTime = System.currentTimeMillis();

            while ((System.currentTimeMillis() - startTime) < expiresIn * 1000L) {
                TimeUnit.SECONDS.sleep(interval);

                parameters.clear();
                parameters.add(new FormRequestBody.Parameter("grant_type", "device_code"));
                parameters.add(new FormRequestBody.Parameter("client_id", code.clientId()));
                parameters.add(new FormRequestBody.Parameter("device_code", deviceCode));

                try (HttpRequest pollRequest = HttpRequest.builder("https://login.microsoftonline.com/consumers/oauth2/v2.0/token")
                        .method("POST")
                        .body(new FormRequestBody(parameters))
                        .build()) {
                    JsonElement json = pollRequest.execute().as(JsonResponseBody.class).getJson();

                    if (!json.isJsonObject())
                        throw new BasicAuthenticationException("Invalid response from device code endpoint.");

                    final JsonObject pollJson = json.getAsJsonObject();

                    if (pollJson.has("access_token")) {
                        return new RefreshTokenResult(
                                pollJson.get("refresh_token").getAsString(),
                                new XboxAuthStep(pollJson.get("access_token").getAsString()).login()
                        );
                    }

                    if (pollJson.has("error")) {
                        final String error = pollJson.get("error").getAsString();
                        if (error.equals("slow_down"))
                            interval += 5;
                        else if (!error.equals("authorization_pending"))
                            throw new BasicAuthenticationException("Device code flow error: " + error);
                    }
                }
            }

            throw new BasicAuthenticationException("Device code login timed out.");
        } catch (Exception e) {
            throw new BasicAuthenticationException("Device code flow failed", e);
        }
    }
}
