plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    kotlin("plugin.serialization") version "2.2.0"
    id("maven-publish")
}

// Resolve the library version: -PttClientVersion / TT_CLIENT_VERSION env var ->
// git describe --tags --match v* -> 0.0.0-git fallback. This is an AAR, so there
// is no Android versionCode.
fun resolveTtClientVersion(project: Project): String {
    val override = (project.findProperty("ttClientVersion") as String?)
        ?: System.getenv("TT_CLIENT_VERSION")
    if (!override.isNullOrBlank()) {
        return override.trim()
    }
    return try {
        val proc = ProcessBuilder("git", "describe", "--tags", "--match", "v*")
            .directory(project.rootDir)
            .start()
        proc.waitFor()
        val described = proc.inputStream.bufferedReader().readText().trim()
        if (proc.exitValue() == 0 && described.isNotEmpty()) {
            described.removePrefix("v")
        } else {
            "0.0.0-git"
        }
    } catch (ignored: Exception) {
        "0.0.0-git"
    }
}

val ttClientVersion = resolveTtClientVersion(project)
version = ttClientVersion

android {
    namespace = "com.adguard.trusttunnel"
    compileSdk = 35
    ndkVersion = "29.0.14206865"

    defaultConfig {
        minSdk = 26

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("proguard-rules.pro")
        externalNativeBuild {
            cmake {
                targets += "trusttunnel_android"
                arguments += "-DANDROID_STL=c++_static"
                arguments += "-DCMAKE_BUILD_TYPE=RelWithDebInfo"
                arguments += "-DTT_CLIENT_VERSION=$ttClientVersion"
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }
}

dependencies {
    // Logging
    implementation("org.slf4j:slf4j-api:1.7.25")
    implementation("com.github.tony19:logback-android:2.0.0")
    implementation("io.reactivex.rxjava3:rxandroid:3.0.0")

    implementation("com.akuleshov7:ktoml-core:0.7.0")
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                groupId = "com.adguard.trusttunnel"
                artifactId = "trusttunnel-client-android"
            }
        }
        repositories {
            maven {
                name = "GitHubPackages"
                url = uri("https://maven.pkg.github.com/TrustTunnel/TrustTunnelClient")
                credentials {
                    username = providers.gradleProperty("gpr.user")
                        .orElse(providers.environmentVariable("USERNAME"))
                        .orNull
                    password = providers.gradleProperty("gpr.key")
                        .orElse(providers.environmentVariable("TOKEN"))
                        .orNull
                }
            }
        }
    }
}
