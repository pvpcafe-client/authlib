/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.result;

import java.util.Objects;
import java.util.UUID;

public final class MinecraftSessionAuthResult implements MicrosoftAuthResult {
    private final String username;
    private final UUID uuid;
    private final String session;

    public MinecraftSessionAuthResult(
            String username,
            UUID uuid,
            String session
    ) {
        this.username = username;
        this.uuid = uuid;
        this.session = session;
    }

    public String username() {
        return username;
    }

    public UUID uuid() {
        return uuid;
    }

    public String session() {
        return session;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) return true;
        if (obj == null || obj.getClass() != this.getClass()) return false;
        MinecraftSessionAuthResult that = (MinecraftSessionAuthResult) obj;
        return Objects.equals(this.username, that.username) &&
                Objects.equals(this.uuid, that.uuid) &&
                Objects.equals(this.session, that.session);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username, uuid, session);
    }

    @Override
    public String toString() {
        return "MinecraftSessionAuthResult{" +
                "username='" + username + '\'' +
                ", uuid=" + uuid +
                ", session='" + session + '\'' +
                '}';
    }

    public static MinecraftSessionAuthResult unwrap(MicrosoftAuthResult result) {
        if (result instanceof RefreshTokenResult) {
            final MicrosoftAuthResult refreshResult = ((RefreshTokenResult) result).result();
            if (refreshResult instanceof MinecraftSessionAuthResult)
                return (MinecraftSessionAuthResult) refreshResult;
        } else if (result instanceof MinecraftSessionAuthResult) {
            return (MinecraftSessionAuthResult) result;
        }
        throw new IllegalStateException("Expected a Minecraft session");
    }

}