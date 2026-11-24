# Android core

The Rust core follows Flowseal tg-ws-proxy 1.12.0 at commit `3fc8b9ee984fc36f52d59b2323735dc8d681864d`.

The core supports direct WS pools, CF Worker → CF media H2 → CF WS → TCP fallback, production and test DCs, three MTProto framing modes, FakeTLS, and PROXY protocol v1. Android settings expose H2, Worker and CF domain lists, TLS/port 80, test DCs, FakeTLS, socket buffers, and PROXY protocol. TLS and H2 start enabled. Existing saved proxy addresses and secrets continue to load.

H2 uses one shared client per DC/domain, bounded requests and response memory, exact-ciphertext recovery, capacity rotation, transport error delivery, and a timed preflight before consuming native packets. Plaintext authentication packets stay outside replay history. FakeTLS mirrors cipher suites and X25519/hybrid key shares, profiles the masking site's first encrypted record, and rejects ClientHello replay across proxy restarts.

For Android power usage, idle WS and Worker preconnections expire after two minutes or less. A new request replenishes them. H2 recovery checks run once per second while recovery work exists. The foreground service uses 15-second traffic updates and 60-second idle updates. Native tasks and runtime threads end on stop. Logcat collection follows the visible activity lifecycle and handles reader shutdown failures. The foreground service persists the requested running state and restores saved settings on a sticky restart. The service uses Android's normal power management.

## Build and check

Install JDK 21, Android SDK 35, NDK `28.2.13676358`, Rust, and the `aarch64-linux-android` and `armv7-linux-androideabi` Rust targets. Configure the SDK with `ANDROID_HOME` or `local.properties`.

The Gradle `preBuild` task builds the Rust libraries with `Cargo.lock` and packages them from `app/build/generated/rustJniLibs`. The committed legacy `.so` files are superseded by these generated outputs.

On Windows run `gradlew.bat :app:assembleUniversalDebug :app:testUniversalDebugUnitTest :app:lintUniversalDebug`. On Linux/macOS, the included wrapper can be invoked directly:

```sh
java -classpath gradle/wrapper/gradle-wrapper.jar org.gradle.wrapper.GradleWrapperMain :app:assembleUniversalDebug :app:testUniversalDebugUnitTest :app:lintUniversalDebug
cargo test --locked
```

The Android unit tests use Robolectric and build a host Rust library through `buildRustHostForTests` to verify service lifecycle transitions with a real native listener.

The universal APK is written to `app/build/outputs/apk/universal/debug/app-universal-debug.apk`. ARM32 and ARM64 flavors remain available.

Rust regression tests exercise native framing, H2 sharing/cancellation/recovery, error propagation, bounded permits, TCP backoff, Worker cooldowns, FakeTLS fragmentation, and ClientHello replay. Device testing should measure Android heap retention, battery consumption, network handover, and Doze behavior with Telegram traffic. The host tests cover native lifecycle and transport behavior.

Source and attribution are available in the upstream repository. The upstream MIT notice is also included in APK resources.

https://github.com/Flowseal/tg-ws-proxy/tree/3fc8b9ee984fc36f52d59b2323735dc8d681864d
