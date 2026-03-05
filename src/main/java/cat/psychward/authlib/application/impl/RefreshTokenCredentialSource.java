/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.application.impl;

import cat.psychward.authlib.application.api.ClientCredentialSource;
import cat.psychward.authlib.application.api.CredentialSource;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.flow.steps.TokenAuthStep;

import java.util.Objects;

public final class RefreshTokenCredentialSource implements CredentialSource {
    private final ClientCredentialSource owner;
    private final String refreshToken;

    public RefreshTokenCredentialSource(
            ClientCredentialSource owner,
            String refreshToken
    ) {
        this.owner = owner;
        this.refreshToken = refreshToken;
    }

    public ClientCredentialSource owner() {
        return owner;
    }

    public String refreshToken() {
        return refreshToken;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        RefreshTokenCredentialSource that = (RefreshTokenCredentialSource) obj;
        return Objects.equals(this.owner, that.owner) &&
                Objects.equals(this.refreshToken, that.refreshToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(owner, refreshToken);
    }

    @Override
    public String toString() {
        return "RefreshTokenCredentialSource{" +
                "owner=" + owner +
                ", refreshToken='" + refreshToken + '\'' +
                '}';
    }

    @Override
    public MicrosoftAuthStep initiate() {
        return new TokenAuthStep(owner, refreshToken, TokenAuthStep.Type.REFRESH_TOKEN);
    }

}