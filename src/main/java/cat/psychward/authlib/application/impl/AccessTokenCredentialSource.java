/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.application.impl;

import cat.psychward.authlib.application.api.CredentialSource;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.flow.steps.MinecraftAuthStep;
import com.google.gson.annotations.SerializedName;

import java.util.Objects;

public final class AccessTokenCredentialSource implements CredentialSource {

    @SerializedName("accessToken")
    private final String accessToken;

    public AccessTokenCredentialSource(String accessToken) {
        this.accessToken = accessToken;
    }

    public String accessToken() {
        return accessToken;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        AccessTokenCredentialSource that = (AccessTokenCredentialSource) obj;
        return Objects.equals(this.accessToken, that.accessToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(accessToken);
    }

    @Override
    public String toString() {
        return "AccessTokenCredentialSource{" +
                "accessToken='" + accessToken + '\'' +
                '}';
    }

    @Override
    public MicrosoftAuthStep initiate() {
        return new MinecraftAuthStep(this.accessToken);
    }

}