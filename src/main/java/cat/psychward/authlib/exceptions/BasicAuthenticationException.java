/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.exceptions;

public final class BasicAuthenticationException extends AuthenticationException {

    public BasicAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

    public BasicAuthenticationException(Throwable cause) {
        super(cause);
    }

    public BasicAuthenticationException(String message) {
        super(message);
    }
}
