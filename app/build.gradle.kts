import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.amurcanov.tgwsproxy"
    compileSdk = 35
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "com.amurcanov.tgwsproxy"
        targetSdk = 35
        versionCode = 123
        versionName = "1.2.3"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    flavorDimensions.add("arch")
    productFlavors {
        create("arm32") {
            dimension = "arch"
            minSdk = 21
            ndk {
                abiFilters.clear()
                abiFilters.add("armeabi-v7a")
            }
        }
        create("arm64") {
            dimension = "arch"
            minSdk = 24
            ndk {
                abiFilters.clear()
                abiFilters.add("arm64-v8a")
            }
        }
        create("universal") {
            dimension = "arch"
            minSdk = 21
            ndk {
                abiFilters.clear()
                abiFilters.addAll(listOf("arm64-v8a", "armeabi-v7a"))
            }
        }
    }

    val localProperties = Properties()
    val localPropertiesFile = rootProject.file("local.properties")
    if (localPropertiesFile.exists()) {
        localProperties.load(localPropertiesFile.inputStream())
    }

    signingConfigs {
        create("release") {
            val keyFile = localProperties.getProperty("KEYSTORE_FILE")
            if (keyFile != null) {
                // Резолвим путь: если начинается с "..", берём от корня проекта
                val resolvedFile = if (keyFile.startsWith("..")) {
                    // ../release.keystore -> корень проекта / release.keystore
                    file(rootDir.resolve(keyFile.substring(3)))
                } else {
                    file(keyFile)
                }
                if (resolvedFile.exists()) {
                    storeFile = resolvedFile
                    storePassword = localProperties.getProperty("KEYSTORE_PASSWORD")
                    keyAlias = localProperties.getProperty("KEY_ALIAS")
                    keyPassword = localProperties.getProperty("KEY_PASSWORD")
                } else {
                    println("WARNING: Keystore file not found: $keyFile (resolved: ${resolvedFile.absolutePath})")
                }
            }
            enableV1Signing = true
            enableV2Signing = true
            enableV3Signing = true
        }
    }

    buildTypes {
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            val keyFile = localProperties.getProperty("KEYSTORE_FILE")
            val resolvedFile = if (keyFile != null && keyFile.startsWith("..")) {
                file(rootDir.resolve(keyFile.substring(3)))
            } else if (keyFile != null) {
                file(keyFile)
            } else null
            
            if (resolvedFile != null && resolvedFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
                println("✅ Signing config applied: ${resolvedFile.absolutePath}")
            } else {
                println("⚠️ WARNING: Keystore not found, using debug signing")
                println("   Looked for: ${resolvedFile?.absolutePath ?: keyFile}")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    // composeOptions removed — AGP 9.x handles Compose compiler internally
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
    sourceSets {
        getByName("main") {
            jniLibs.setSrcDirs(listOf(layout.buildDirectory.dir("generated/rustJniLibs")))
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")

    // DataStore for persistent settings
    implementation("androidx.datastore:datastore-preferences:1.1.1")

    // JNA for easy C-shared library calls
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    debugImplementation("com.squareup.leakcanary:leakcanary-android:2.14")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.appcompat:appcompat:1.6.1")
}

// Build from Rust sources so an APK always contains the C ABI used by NativeProxy.
val nativeOutput = layout.buildDirectory.dir("generated/rustJniLibs")
val cargoOutput = rootProject.layout.projectDirectory.dir("target")
val ndkDirectory = androidComponents.sdkComponents.ndkDirectory
val hostSystem = System.getProperty("os.name").lowercase()
val ndkHost = when {
    hostSystem.contains("windows") -> "windows-x86_64"
    hostSystem.contains("mac") -> "darwin-x86_64"
    else -> "linux-x86_64"
}
val clangSuffix = if (hostSystem.contains("windows")) ".cmd" else ""
val executableSuffix = if (hostSystem.contains("windows")) ".exe" else ""
val buildRust = tasks.register<Exec>("buildRust") {
    workingDir(rootProject.layout.projectDirectory)
    inputs.files(rootProject.fileTree("src") { include("**/*.rs") })
    inputs.files(rootProject.file("Cargo.toml"), rootProject.file("Cargo.lock"))
    inputs.property("ndkVersion", android.ndkVersion.orEmpty())
    outputs.files(
        cargoOutput.file("aarch64-linux-android/release/libtgwsproxy.so"),
        cargoOutput.file("armv7-linux-androideabi/release/libtgwsproxy.so")
    )
    commandLine("cargo", "build", "--locked", "--release", "--jobs", "4",
        "--target", "aarch64-linux-android", "--target", "armv7-linux-androideabi")
    val ndkPath = ndkDirectory
    val host = ndkHost
    val clangExtension = clangSuffix
    val binaryExtension = executableSuffix
    val targetPath = cargoOutput.asFile.absolutePath
    doFirst {
        val bin = ndkPath.get().dir("toolchains/llvm/prebuilt/$host/bin").asFile
        val arm64 = bin.resolve("aarch64-linux-android24-clang$clangExtension").absolutePath
        val arm32 = bin.resolve("armv7a-linux-androideabi21-clang$clangExtension").absolutePath
        val archiver = bin.resolve("llvm-ar$binaryExtension").absolutePath
        environment("CARGO_TARGET_DIR", targetPath)
        environment("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER", arm64)
        environment("CC_aarch64_linux_android", arm64)
        environment("AR_aarch64_linux_android", archiver)
        environment("CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER", arm32)
        environment("CC_armv7_linux_androideabi", arm32)
        environment("AR_armv7_linux_androideabi", archiver)
    }
}
val syncRustLibraries = tasks.register<Sync>("syncRustLibraries") {
    dependsOn(buildRust)
    from(cargoOutput.file("aarch64-linux-android/release/libtgwsproxy.so")) { into("arm64-v8a") }
    from(cargoOutput.file("armv7-linux-androideabi/release/libtgwsproxy.so")) { into("armeabi-v7a") }
    into(nativeOutput)
}
tasks.named("preBuild") { dependsOn(syncRustLibraries) }
