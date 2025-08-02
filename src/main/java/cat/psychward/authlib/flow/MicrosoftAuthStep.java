/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.flow;

import cat.psychward.authlib.exceptions.AuthenticationException;
import cat.psychward.authlib.result.MicrosoftAuthResult;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

public abstract class MicrosoftAuthStep {

    private static final Executor SERVICE = Executors.newVirtualThreadPerTaskExecutor();

    public abstract MicrosoftAuthResult login() throws AuthenticationException;

    public CompletableFuture<MicrosoftAuthResult> loginAsync() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return login();
            } catch (AuthenticationException e) {
                throw new CompletionException(e.getMessage(), e);
            }
        }, SERVICE);
    }

}