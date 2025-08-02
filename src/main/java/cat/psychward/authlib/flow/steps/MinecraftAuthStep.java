/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.flow.steps;

import cat.psychward.authlib.exceptions.AuthenticationException;
import cat.psychward.authlib.exceptions.BasicAuthenticationException;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.result.MicrosoftAuthResult;
import cat.psychward.authlib.result.MinecraftSessionAuthResult;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

public final class MinecraftAuthStep extends MicrosoftAuthStep {

    private final String accessToken;

    public MinecraftAuthStep(String accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public MicrosoftAuthResult login() throws AuthenticationException {
        try (final var client = HttpClients.createDefault()) {
            HttpGet get = new HttpGet("https://api.minecraftservices.com/minecraft/profile");
            get.setHeader("Authorization", "Bearer " + accessToken);
            get.setHeader("Accept", "application/json");

            try (var response = client.execute(get)) {
                if (response.getStatusLine().getStatusCode() != 200)
                    throw new BasicAuthenticationException("Failed to get Minecraft profile: HTTP " + response.getStatusLine().getStatusCode());

                var json = JsonParser.parseReader(new InputStreamReader(response.getEntity().getContent(), StandardCharsets.UTF_8));
                if (!json.isJsonObject())
                    throw new BasicAuthenticationException("Invalid response from Minecraft profile endpoint.");

                final JsonObject profile = json.getAsJsonObject();
                if (profile.has("name") && profile.has("id")) {
                    String username = profile.get("name").getAsString();
                    UUID uuid = UUID.fromString(insertDashes(profile.get("id").getAsString()));

                    return new MinecraftSessionAuthResult(username, uuid, accessToken);
                }

                throw new BasicAuthenticationException("Profile response missing required fields: " + profile);
            }
        } catch (Exception e) {
            throw new BasicAuthenticationException("Failed to fetch Minecraft profile", e);
        }
    }

    private String insertDashes(String rawUuid) {
        return rawUuid.replaceFirst(
                "(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)",
                "$1-$2-$3-$4-$5"
        );
    }
}
