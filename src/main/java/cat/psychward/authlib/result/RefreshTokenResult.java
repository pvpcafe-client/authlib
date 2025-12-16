/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.result;

import java.util.Objects;

public final class RefreshTokenResult implements MicrosoftAuthResult {
    private final String refreshToken;
    private final MicrosoftAuthResult result;

    public RefreshTokenResult(
            String refreshToken,
            MicrosoftAuthResult result
    ) {
        this.refreshToken = refreshToken;
        this.result = result;
    }

    public String refreshToken() {
        return refreshToken;
    }

    public MicrosoftAuthResult result() {
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        RefreshTokenResult that = (RefreshTokenResult) obj;
        return Objects.equals(this.refreshToken, that.refreshToken) &&
                Objects.equals(this.result, that.result);
    }

    @Override
    public int hashCode() {
        return Objects.hash(refreshToken, result);
    }

    @Override
    public String toString() {
        return "RefreshTokenResult{" +
                "refreshToken='" + refreshToken + '\'' +
                ", result=" + result +
                '}';
    }
}