/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
package cat.psychward.authlib.flow.steps.oauth2;

import cat.psychward.authlib.exceptions.AuthenticationException;
import cat.psychward.authlib.flow.steps.TokenAuthStep;
import cat.psychward.authlib.result.MicrosoftAuthResult;
import cat.psychward.authlib.application.impl.OAuthCredentialSource;
import cat.psychward.authlib.exceptions.BasicAuthenticationException;
import cat.psychward.authlib.flow.MicrosoftAuthStep;
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class HTTPServerAuthStep extends MicrosoftAuthStep {

    private static final Pattern CODE_PATTERN = Pattern.compile("code=([^&]*)");
    private static HttpServer server;

    private final OAuthCredentialSource oauth;

    public HTTPServerAuthStep(OAuthCredentialSource oauth) {
        this.oauth = oauth;
    }

    @Override
    public MicrosoftAuthResult login() throws AuthenticationException {
        try {
            if (server != null) server.stop(0);

            server = HttpServer.create(new InetSocketAddress("0.0.0.0", oauth.port()), 1);
        } catch (final Throwable throwable) {
            throw new BasicAuthenticationException("Failed to create server", throwable);
        }

        final CompletableFuture<MicrosoftAuthResult> future = new CompletableFuture<>();

        server.start();
        server.createContext("/", exchange -> {
            if (exchange.getRequestURI().getQuery() == null) return;
            try {
                exchange.sendResponseHeaders(200, "You can close this window now.".length());
                exchange.getResponseBody().write("You can close this window now.".getBytes());
            } catch (Exception ignored) {
            }
            exchange.close();
            if (server != null) server.stop(0);

            try {
                Matcher result = CODE_PATTERN.matcher(exchange.getRequestURI().getQuery());
                if (!result.find() || result.groupCount() < 1)
                    throw new BasicAuthenticationException("Failed to find code in URI.");

                future.complete(new TokenAuthStep(oauth, result.group(1), TokenAuthStep.Type.ACCESS_TOKEN).login());
            } catch (final Exception exception) {
                future.completeExceptionally(exception);
            }
        });

        try {
            return future.get();
        } catch (InterruptedException | ExecutionException e) {
            throw new BasicAuthenticationException("Failed to wait for future", e);
        }
    }
}