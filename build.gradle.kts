plugins {
    id("java")
}

group = "cat.psychward.pvpcafe"
version = "1.1"

repositories {
    mavenCentral()
}

dependencies {
    // version yoinked from minecraft fabric 1.21.8
    implementation("com.google.code.gson:gson:2.11.0")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(8)
}

java {
    withSourcesJar()
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}