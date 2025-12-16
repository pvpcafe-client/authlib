package http.response.impl;

import cat.psychward.http.response.ResponseBody;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public final class JsonResponseBody extends ResponseBody {

    private final JsonElement json;

    public JsonResponseBody(byte[] content) {
        super(content);

        this.json = JsonParser.parseReader(new InputStreamReader(new ByteArrayInputStream(content), StandardCharsets.UTF_8));
    }

    public JsonElement getJson() {
        return json;
    }
}