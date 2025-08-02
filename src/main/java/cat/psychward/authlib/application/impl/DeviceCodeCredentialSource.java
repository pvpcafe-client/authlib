/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.application.impl;

import cat.psychward.authlib.application.CredentialSource;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import cat.psychward.authlib.flow.steps.oauth2.DeviceCodeAuthStep;

import java.util.function.BiConsumer;

public record DeviceCodeCredentialSource(
        String clientId,
        BiConsumer<String, String> deviceCodeConsumer
) implements CredentialSource {

    @Override
    public MicrosoftAuthStep initiate() {
        return new DeviceCodeAuthStep(this);
    }

}
