import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    kotlin("android")
    kotlin("plugin.serialization")
}

fun configured(name: String): String? = providers.gradleProperty(name)
    .orElse(providers.environmentVariable(name))
    .orNull
    ?.trim()
    ?.takeIf { it.isNotEmpty() }

fun quoted(value: String): String = "\"${value.replace("\\", "\\\\").replace("\"", "\\\"")}\""

val releaseKeystore = configured("EMILIA_ANDROID_KEYSTORE_PATH")
val releaseAlias = configured("EMILIA_ANDROID_KEY_ALIAS")
val releaseStorePassword = configured("EMILIA_ANDROID_KEYSTORE_PASSWORD")
val releaseKeyPassword = configured("EMILIA_ANDROID_KEY_PASSWORD")
val releaseSigningReady = listOf(releaseKeystore, releaseAlias, releaseStorePassword, releaseKeyPassword).all { it != null }
val playCloudProject = configured("EMILIA_PLAY_CLOUD_PROJECT_NUMBER") ?: "0"
val releaseVersionName = configured("EMILIA_RELEASE_VERSION") ?: "1.0.0"
val releaseVersionCode = (configured("EMILIA_RELEASE_BUILD_NUMBER") ?: "1").toIntOrNull()
    ?: error("EMILIA_RELEASE_BUILD_NUMBER must be a positive 32-bit integer")
require(playCloudProject.matches(Regex("[0-9]{1,20}"))) { "EMILIA_PLAY_CLOUD_PROJECT_NUMBER must be numeric" }
require(releaseVersionName.matches(Regex("[0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?"))) {
    "EMILIA_RELEASE_VERSION must be a semantic version"
}
require(releaseVersionCode in 1..2_100_000_000) { "EMILIA_RELEASE_BUILD_NUMBER is outside the store range" }

android {
    namespace = "ai.emiliaprotocol.approver"
    compileSdk = 36

    defaultConfig {
        applicationId = "ai.emiliaprotocol.approver"
        minSdk = 33
        targetSdk = 36
        versionCode = releaseVersionCode
        versionName = releaseVersionName
        buildConfigField("String", "API_BASE_URL", quoted("https://www.emiliaprotocol.ai/api/"))
        buildConfigField("long", "PLAY_CLOUD_PROJECT_NUMBER", "${playCloudProject}L")
    }

    signingConfigs {
        if (releaseSigningReady) {
            create("release") {
                storeFile = file(requireNotNull(releaseKeystore))
                storePassword = releaseStorePassword
                keyAlias = releaseAlias
                keyPassword = releaseKeyPassword
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
                enableV4Signing = true
            }
        }
    }

    buildTypes {
        debug {
            versionNameSuffix = "-debug"
            buildConfigField("String", "API_BASE_URL", quoted(configured("EMILIA_MOBILE_API_BASE_URL") ?: "https://www.emiliaprotocol.ai/api/"))
            buildConfigField("boolean", "PRODUCTION_RELEASE", "false")
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release")
            buildConfigField("boolean", "PRODUCTION_RELEASE", "true")
        }
    }

    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_17) } }

dependencies {
    implementation(project(":"))
    implementation("androidx.credentials:credentials:1.6.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.6.0")
    implementation("com.google.android.play:integrity:1.6.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
    testImplementation("junit:junit:4.13.2")
}

tasks.register("verifyProductionIdentity") {
    doLast {
        require(playCloudProject != "0") { "Configure EMILIA_PLAY_CLOUD_PROJECT_NUMBER before a production release" }
        require(releaseSigningReady) { "Configure all EMILIA_ANDROID_KEY* signing values before a production release" }
    }
}

tasks.matching { it.name == "bundleRelease" || it.name == "assembleRelease" }.configureEach {
    dependsOn("verifyProductionIdentity")
}
