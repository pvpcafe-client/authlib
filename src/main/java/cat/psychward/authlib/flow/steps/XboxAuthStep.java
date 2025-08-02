/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.flow.steps;

import cat.psychward.authlib.exceptions.AuthenticationException;
import cat.psychward.authlib.exceptions.BasicAuthenticationException;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.result.MicrosoftAuthResult;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;

import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

@SuppressWarnings("HttpUrlsUsage")
public final class XboxAuthStep extends MicrosoftAuthStep {

    private final String accessToken;
    private static final Gson GSON = new Gson();

    public XboxAuthStep(String accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    public MicrosoftAuthResult login() throws AuthenticationException {
        try {
            final JsonObject xui = getXui(), xsts = getXSTS(xui), mcLogin = loginWithXsts(xsts);

            if (mcLogin.has("access_token"))
                return new MinecraftAuthStep(mcLogin.get("access_token").getAsString()).login();

            throw new BasicAuthenticationException("Minecraft login failed: " + mcLogin);
        } catch (Exception e) {
            throw new BasicAuthenticationException(e);
        }
    }

    private JsonObject getXui() throws Exception {
        JsonObject properties = new JsonObject();
        properties.addProperty("AuthMethod", "RPS");
        properties.addProperty("SiteName", "user.auth.xboxlive.com");
        properties.addProperty("RpsTicket", "d=" + accessToken);

        JsonObject body = new JsonObject();
        body.add("Properties", properties);
        body.addProperty("RelyingParty", "http://auth.xboxlive.com");
        body.addProperty("TokenType", "JWT");

        return postJson("https://user.auth.xboxlive.com/user/authenticate", body);
    }

    private JsonObject getXSTS(JsonObject xui) throws Exception {
        JsonArray userTokens = new JsonArray();
        userTokens.add(xui.get("Token").getAsString());

        JsonObject properties = new JsonObject();
        properties.addProperty("SandboxId", "RETAIL");
        properties.add("UserTokens", userTokens);

        JsonObject body = new JsonObject();
        body.add("Properties", properties);
        body.addProperty("RelyingParty", "rp://api.minecraftservices.com/");
        body.addProperty("TokenType", "JWT");

        return postJson("https://xsts.auth.xboxlive.com/xsts/authorize", body);
    }

    private JsonObject loginWithXsts(JsonObject xsts) throws Exception {
        String token = xsts.get("Token").getAsString();
        String uhs = xsts.getAsJsonObject("DisplayClaims")
                .getAsJsonArray("xui")
                .get(0).getAsJsonObject()
                .get("uhs").getAsString();

        JsonObject body = new JsonObject();
        body.addProperty("identityToken", "XBL3.0 x=" + uhs + ";" + token);
        body.addProperty("ensureLegacyEnabled", true);

        return postJson("https://api.minecraftservices.com/authentication/login_with_xbox", body);
    }

    private JsonObject postJson(String url, JsonObject body) throws Exception {
        try (final var client = HttpClients.createDefault()) {
            HttpPost post = new HttpPost(url);
            post.setHeader("Content-Type", "application/json");
            post.setHeader("Accept", "application/json");
            post.setEntity(new StringEntity(GSON.toJson(body), StandardCharsets.UTF_8));

            try (var response = client.execute(post)) {
                var json = JsonParser.parseReader(new InputStreamReader(response.getEntity().getContent(), StandardCharsets.UTF_8));
                return json.isJsonObject() ? json.getAsJsonObject() : new JsonObject();
            }
        }
    }
}
