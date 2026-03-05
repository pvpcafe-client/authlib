/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.http.response.impl;

import cat.psychward.http.response.ResponseBody;
import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public final class JsonResponseBody extends ResponseBody {

    private final JsonElement json;

    public JsonResponseBody(byte[] content) {
        super(content);

        JsonElement parsed;
        try {
            parsed = JsonParser.parseReader(new InputStreamReader(new ByteArrayInputStream(content), StandardCharsets.UTF_8));
        } catch (final NoSuchMethodError ignored) {
            try {
                //noinspection deprecation -- needed because i'd prefer supporting older versions of gson too
                parsed = new JsonParser().parse(new InputStreamReader(new ByteArrayInputStream(content), StandardCharsets.UTF_8));
            } catch (final NoSuchMethodError ignored2) {
                parsed = new Gson().fromJson(new InputStreamReader(new ByteArrayInputStream(content), StandardCharsets.UTF_8), JsonElement.class);
            }
        }

        assert parsed != null;
        this.json = parsed;
    }

    public JsonElement getJson() {
        return json;
    }
}