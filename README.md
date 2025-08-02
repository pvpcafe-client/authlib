# authlib
Microsoft authentication library for PvPCafe Client.

## example usage
### including the library in your project using gradle
```kts
repositories {
    maven("https://jitpack.io")
}

dependencies {
    implementation("com.github.pvpcafe-client:authlib:1.0")
}
```

### using the library
```java
// also supports refresh token login or oauth2 azure application login (public, private)
public void deviceCodeLoginExample() {
    final CredentialSource source = new DeviceCodeCredentialSource(
            "CLIENT_ID_HERE",
            (uri, code) -> System.out.println("Verify with code " + code + " at " + uri)
    );

    // asynchronous login
    source.initiate().loginAsync().thenAcceptAsync((MicrosoftAuthResult result) -> {
        final MinecraftSessionAuthResult session = MinecraftSessionAuthResult.unwrap(result);

        // apply the session to your game, usually via an accessor
    }).exceptionallyAsync(throwable -> {
        throw new RuntimeException("Failed to authenticate", throwable);
    });

    // synchronous login
    try {
        final MicrosoftAuthResult result = source.initiate().login();
        final MinecraftSessionAuthResult session = MinecraftSessionAuthResult.unwrap(result);

        // apply the session to your game, usually via an accessor
    } catch (Throwable throwable) {
        throw new RuntimeException("Failed to authenticate", throwable);
    }
}
```

## License
Licensed under Mozilla Public License 2.0 ([LICENSE](LICENSE)).