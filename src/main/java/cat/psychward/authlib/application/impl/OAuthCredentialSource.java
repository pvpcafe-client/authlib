/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.application.impl;

import cat.psychward.authlib.application.api.ClientCredentialSource;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.flow.steps.oauth2.HTTPServerAuthStep;
import cat.psychward.http.request.impl.FormRequestBody;
import com.google.gson.annotations.SerializedName;
import org.jetbrains.annotations.Nullable;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class OAuthCredentialSource implements ClientCredentialSource {

    private static final Pattern PATTERN = Pattern.compile(".*:([0-9]{1,5}).*");
    private static final int PORT_LIMIT = 65535;

    @Nullable
    @SerializedName("port")
    private final Integer port;

    @SerializedName("redirectUri")
    private final String redirectUri;

    @SerializedName("clientId")
    private final String clientId;

    @Nullable
    @SerializedName("clientSecret")
    private final String clientSecret;

    @Nullable
    @SerializedName("scope")
    private final String scope;

    public OAuthCredentialSource(
            String redirectUri,
            String clientId,
            @Nullable String clientSecret,
            @Nullable String scope
    ) {
        this.redirectUri = redirectUri;
        this.port = this.extractPort(redirectUri);
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.scope = scope;
    }

    public OAuthCredentialSource(
            String redirectUri,
            String clientId,
            @Nullable String clientSecret
    ) {
        this(redirectUri, clientId, clientSecret, null);
    }

    public OAuthCredentialSource(int port, String clientId, String clientSecret) {
        this("http://localhost:" + port, clientId, clientSecret, null);
    }

    public OAuthCredentialSource(String redirectUri, String clientId) {
        this(redirectUri, clientId, null);
    }

    public OAuthCredentialSource(int port, String clientId) {
        this(port, clientId, null);
    }

    private @Nullable Integer extractPort(String redirectUri) {
        final Matcher matcher = PATTERN.matcher(redirectUri);
        if (matcher.find()) {
            int value = Integer.parseInt(matcher.group(1));
            if (value < 0 || value > PORT_LIMIT)
                throw new IllegalArgumentException("Invalid port: " + value + " (out of valid port range)");

            return value;
        } else {
            return null;
        }
    }

    public int port() {
        final Integer port = this.port;
        return port == null ? -1 : port;
    }

    public String clientId() {
        return clientId;
    }

    public Optional<String> clientSecret() {
        return Optional.ofNullable(clientSecret);
    }

    public Optional<String> scope() {
        return Optional.ofNullable(scope);
    }

    @Override
    public void appendParameters(List<FormRequestBody.Parameter> parameters) {
        parameters.add(new FormRequestBody.Parameter("client_id", clientId));
        clientSecret().ifPresent(secret -> parameters.add(new FormRequestBody.Parameter("client_secret", secret)));
        scope().ifPresent(scope -> parameters.add(new FormRequestBody.Parameter("scope", scope)));
        parameters.add(new FormRequestBody.Parameter("redirect_uri", redirectUri));
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || getClass() != o.getClass()) return false;
        OAuthCredentialSource that = (OAuthCredentialSource) o;
        return Objects.equals(port, that.port) &&
                Objects.equals(redirectUri, that.redirectUri) &&
                Objects.equals(clientId, that.clientId) &&
                Objects.equals(clientSecret, that.clientSecret);
    }

    @Override
    public int hashCode() {
        return Objects.hash(port, redirectUri, clientId, clientSecret);
    }

    @Override
    public String toString() {
        return "OAuthCredentialSource{" +
                "port=" + port +
                ", redirectUri='" + redirectUri + '\'' +
                ", clientId='" + clientId + '\'' +
                ", clientSecret='" + clientSecret + '\'' +
                '}';
    }

    @Override
    public MicrosoftAuthStep initiate() {
        if (this.port == null || this.port < 0 || this.port > PORT_LIMIT)
            throw new IllegalStateException("invalid port");

        return new HTTPServerAuthStep(this);
    }

    public String buildUrl() {
        return String.format("https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize?client_id=%s&response_type=code&redirect_uri=%s&scope=XboxLive.signin%%20XboxLive.offline_access&state=NOT_NEEDED", clientId, redirectUri());
    }

    public String redirectUri() {
        return redirectUri;
    }
}