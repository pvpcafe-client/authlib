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

    private static Executor executor;

    public static void setExecutor(Executor executor) {
        MicrosoftAuthStep.executor = executor;
    }

    public abstract MicrosoftAuthResult login() throws AuthenticationException;

    public CompletableFuture<MicrosoftAuthResult> loginAsync() {
        if (executor == null)
            executor = Executors.newSingleThreadExecutor();

        return CompletableFuture.supplyAsync(() -> {
            try {
                return login();
            } catch (AuthenticationException e) {
                throw new CompletionException(e.getMessage(), e);
            }
        }, executor);
    }

}