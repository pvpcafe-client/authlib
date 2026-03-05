/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.application.impl;

import cat.psychward.authlib.application.api.ClientCredentialSource;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.flow.steps.oauth2.DeviceCodeAuthStep;
import cat.psychward.http.request.impl.FormRequestBody;
import com.google.gson.annotations.SerializedName;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiConsumer;

public final class DeviceCodeCredentialSource implements ClientCredentialSource {

    @SerializedName("clientId")
    private final String clientId;

    private transient BiConsumer<String, String> deviceCodeConsumer;

    public DeviceCodeCredentialSource(String clientId) {
        this.clientId = clientId;
    }

    public DeviceCodeCredentialSource onCodeReceived(BiConsumer<String, String> deviceCodeConsumer) {
        if (this.deviceCodeConsumer == null)
            this.deviceCodeConsumer = deviceCodeConsumer;

        return this;
    }

    public String clientId() {
        return clientId;
    }

    @Override
    public Optional<String> clientSecret() {
        return Optional.empty();
    }

    @Override
    public void appendParameters(List<FormRequestBody.Parameter> parameters) {
        parameters.add(new FormRequestBody.Parameter("client_id", clientId));
    }

    public BiConsumer<String, String> deviceCodeConsumer() {
        return deviceCodeConsumer;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        DeviceCodeCredentialSource that = (DeviceCodeCredentialSource) obj;
        return Objects.equals(this.clientId, that.clientId) &&
                Objects.equals(this.deviceCodeConsumer, that.deviceCodeConsumer);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId, deviceCodeConsumer);
    }

    @Override
    public String toString() {
        return "DeviceCodeCredentialSource{" +
                "clientId='" + clientId + '\'' +
                ", deviceCodeConsumer=" + deviceCodeConsumer +
                '}';
    }

    @Override
    public MicrosoftAuthStep initiate() {
        if (deviceCodeConsumer == null)
            throw new IllegalStateException("deviceCodeConsumer cannot be null");

        return new DeviceCodeAuthStep(this);
    }
}
