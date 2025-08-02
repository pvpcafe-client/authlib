/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.application.impl;

import cat.psychward.authlib.application.CredentialSource;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.flow.steps.RefreshTokenAuthStep;

public record RefreshTokenCredentialSource(
        OAuthCredentialSource owner,
        String refreshToken
) implements CredentialSource {

    @Override
    public MicrosoftAuthStep initiate() {
        return new RefreshTokenAuthStep(owner, refreshToken);
    }

}