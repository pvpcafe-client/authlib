plugins {
    id("java")
    id("java-library")
}

group = "cat.psychward.pvpcafe"
version = "1.2"

repositories {
    maven("https://jitpack.io")
    mavenCentral()
}

dependencies {
    // version yoinked from minecraft fabric 1.21.8
    implementation("com.google.code.gson:gson:2.11.0")

    api("com.github.pvpcafe-client:httplib:1.0.0")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(8)
}

java {
    withSourcesJar()
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}