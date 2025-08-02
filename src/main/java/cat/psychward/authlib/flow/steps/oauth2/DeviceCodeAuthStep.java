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
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

public final class DeviceCodeAuthStep extends MicrosoftAuthStep {

    private final DeviceCodeCredentialSource code;

    public DeviceCodeAuthStep(DeviceCodeCredentialSource code) {
        this.code = code;
    }

    @Override
    public MicrosoftAuthResult login() throws AuthenticationException {
        try (final var client = HttpClients.createDefault()) {

            final var deviceCodeRequest = new HttpPost("https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode");
            deviceCodeRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");

            String body = "client_id=" + code.clientId() +
                    "&scope=XboxLive.signin offline_access";

            deviceCodeRequest.setEntity(new StringEntity(body, StandardCharsets.UTF_8));

            final JsonObject deviceCodeJson;
            try (var response = client.execute(deviceCodeRequest)) {
                deviceCodeJson = JsonParser.parseReader(new InputStreamReader(
                        response.getEntity().getContent(), StandardCharsets.UTF_8)).getAsJsonObject();
            }

            if (!deviceCodeJson.has("device_code") || !deviceCodeJson.has("user_code") ||
                    !deviceCodeJson.has("interval") || !deviceCodeJson.has("expires_in"))
                throw new BasicAuthenticationException("Failed to retrieve device code: " + deviceCodeJson);

            final String deviceCode = deviceCodeJson.get("device_code").getAsString(),
                    userCode = deviceCodeJson.get("user_code").getAsString();

            int interval = deviceCodeJson.get("interval").getAsInt(),
                    expiresIn = deviceCodeJson.get("expires_in").getAsInt();

            code.deviceCodeConsumer().accept(
                    deviceCodeJson.get("verification_uri").getAsString(),
                    userCode
            );

            final var startTime = System.currentTimeMillis();

            while ((System.currentTimeMillis() - startTime) < expiresIn * 1000L) {
                TimeUnit.SECONDS.sleep(interval);

                final HttpPost pollRequest = new HttpPost("https://login.microsoftonline.com/consumers/oauth2/v2.0/token");
                pollRequest.setHeader("Content-Type", "application/x-www-form-urlencoded");

                pollRequest.setEntity(new StringEntity("grant_type=device_code&client_id=" + code.clientId() +
                        "&device_code=" + deviceCode, StandardCharsets.UTF_8));

                final JsonObject pollJson;
                try (var pollResponse = client.execute(pollRequest)) {
                    pollJson = JsonParser.parseReader(new InputStreamReader(
                            pollResponse.getEntity().getContent(), StandardCharsets.UTF_8)).getAsJsonObject();
                }

                if (pollJson.has("access_token")) {
                    return new RefreshTokenResult(
                            pollJson.get("refresh_token").getAsString(),
                            new XboxAuthStep(pollJson.get("access_token").getAsString()).login()
                    );
                }

                if (pollJson.has("error")) {
                    final var error = pollJson.get("error").getAsString();
                    if (error.equals("slow_down"))
                        interval += 5;
                    else if (!error.equals("authorization_pending"))
                        throw new BasicAuthenticationException("Device code flow error: " + error);
                }
            }

            throw new BasicAuthenticationException("Device code login timed out.");
        } catch (Exception e) {
            throw new BasicAuthenticationException("Device code flow failed", e);
        }
    }
}
