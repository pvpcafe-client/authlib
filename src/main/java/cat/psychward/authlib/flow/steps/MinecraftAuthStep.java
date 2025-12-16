/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.flow.steps;

import cat.psychward.authlib.exceptions.AuthenticationException;
import cat.psychward.authlib.exceptions.BasicAuthenticationException;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.http.request.HttpRequest;
import cat.psychward.http.response.HttpResponse;
import cat.psychward.http.response.impl.JsonResponseBody;
import cat.psychward.authlib.result.MicrosoftAuthResult;
import cat.psychward.authlib.result.MinecraftSessionAuthResult;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.UUID;

public final class MinecraftAuthStep extends MicrosoftAuthStep {

    private final String accessToken;

    public MinecraftAuthStep(String accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public MicrosoftAuthResult login() throws AuthenticationException {
        try (final HttpRequest request = HttpRequest.builder()
                .url("https://api.minecraftservices.com/minecraft/profile")
                .setHeader("Authorization", "Bearer " + accessToken)
                .setHeader("Accept", "application/json")
                .method("GET")
                .build()) {

            final HttpResponse response = request.execute();

            if (response.statusCode() != 200)
                throw new BasicAuthenticationException("Failed to get Minecraft profile: HTTP " + response.statusCode() + ", " + response.message());

            JsonElement json = response.as(JsonResponseBody.class).getJson();
            if (!json.isJsonObject())
                throw new BasicAuthenticationException("Invalid response from Minecraft profile endpoint.");

            final JsonObject profile = json.getAsJsonObject();
            if (profile.has("name") && profile.has("id")) {
                String username = profile.get("name").getAsString();
                UUID uuid = UUID.fromString(insertDashes(profile.get("id").getAsString()));

                return new MinecraftSessionAuthResult(username, uuid, accessToken);
            }

            throw new BasicAuthenticationException("Profile response missing required fields: " + profile);
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
