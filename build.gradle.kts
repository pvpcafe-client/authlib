plugins {
    id("java")
}

group = "cat.psychward.pvpcafe"
version = "1.0"

repositories {
    mavenCentral()
}

dependencies {
    // versions yoinked from minecraft fabric 1.21.8
    implementation("com.google.code.gson:gson:2.11.0")
    implementation("org.apache.httpcomponents:httpclient:4.5.14")
    implementation("org.apache.httpcomponents:httpcore:4.4.16")
}

tasks.withType<JavaCompile>().configureEach {
    options.release.set(21)
}

java {
    withSourcesJar()
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}