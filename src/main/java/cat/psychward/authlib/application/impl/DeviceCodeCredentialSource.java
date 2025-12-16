/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.application.impl;

import cat.psychward.authlib.application.CredentialSource;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.flow.steps.oauth2.DeviceCodeAuthStep;

import java.util.Objects;
import java.util.function.BiConsumer;

public final class DeviceCodeCredentialSource implements CredentialSource {
    private final String clientId;
    private final BiConsumer<String, String> deviceCodeConsumer;

    public DeviceCodeCredentialSource(String clientId, BiConsumer<String, String> deviceCodeConsumer) {
        this.clientId = clientId;
        this.deviceCodeConsumer = deviceCodeConsumer;
    }

    public String clientId() {
        return clientId;
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
        return new DeviceCodeAuthStep(this);
    }
}
