/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.result;

import java.util.UUID;

public record MinecraftSessionAuthResult(
        String username,
        UUID uuid,
        String session
) implements MicrosoftAuthResult {

    public static MinecraftSessionAuthResult unwrap(MicrosoftAuthResult result) {
        if (result instanceof RefreshTokenResult refresh) {
            if (refresh.result() instanceof MinecraftSessionAuthResult mc) {
                return mc;
            }
        } else if (result instanceof MinecraftSessionAuthResult mc) {
            return mc;
        }
        throw new IllegalStateException("Expected a Minecraft session");
    }

}