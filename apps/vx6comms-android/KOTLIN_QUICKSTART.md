# VX6 Comms Android Kotlin Quickstart

This guide shows how to start a Kotlin Android chat app that embeds VX6 directly with no external API server.

The app calls the Go mobile bridge in `./mobile`, packaged as:

```text
apps/vx6comms-android/app/libs/vx6mobile.aar
```

## 1. Build the VX6 Android Library

From the repository root:

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
scripts/build_android_mobile.sh
```

This builds:

```text
apps/vx6comms-android/app/libs/vx6mobile.aar
```

Supported targets in the script:

- `android/arm64`: modern real Android phones
- `android/amd64`: Android emulator

## 2. Create Android Project

Use Android Studio:

1. New Project
2. Empty Activity
3. Language: Kotlin
4. UI: Jetpack Compose
5. Minimum SDK: 26 or newer

Recommended package:

```text
tech.vx6.comms
```

## 3. Add AAR Dependency

Copy or keep the generated AAR here:

```text
app/libs/vx6mobile.aar
```

In `app/build.gradle.kts`:

```kotlin
android {
    namespace = "tech.vx6.comms"
    compileSdk = 36

    defaultConfig {
        applicationId = "tech.vx6.comms"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }
}

dependencies {
    implementation(files("libs/vx6mobile.aar"))

    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
}
```

If Gradle cannot resolve the local AAR, add this to the project-level repositories:

```kotlin
repositories {
    google()
    mavenCentral()
    flatDir {
        dirs("app/libs")
    }
}
```

## 4. Android Permissions

In `AndroidManifest.xml`:

```xml
<uses-permission android:name="android.permission.INTERNET" />
<uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
```

Inside `<application>`:

```xml
<service
    android:name=".VX6NodeService"
    android:exported="false"
    android:foregroundServiceType="dataSync" />
```

## 5. Kotlin Bridge Usage

`gomobile bind` exposes the Go package as Java/Kotlin bindings. For this package, expect usage similar to:

```kotlin
import mobile.Mobile
import mobile.Engine
```

Create one engine instance:

```kotlin
val configPath = File(filesDir, "vx6/config.json").absolutePath
val engine: Engine = Mobile.newEngine(configPath)
```

Initialize a VX6 node:

```kotlin
val dataDir = File(filesDir, "vx6/data").absolutePath
val downloadsDir = File(filesDir, "vx6/downloads").absolutePath

val resultJson = engine.init(
    "alice",
    "[::]:4242",
    "",          // advertise address; set explicitly for direct peer tests
    dataDir,
    downloadsDir
)
```

Start and stop the VX6 runtime:

```kotlin
engine.startNode()
engine.stopNode()
```

Generate an invite:

```kotlin
val invite = engine.generateChatInvite()
```

Accept an invite:

```kotlin
val contactJson = engine.acceptChatInvite(inviteFromPeer)
```

Send a message:

```kotlin
val envelopeJson = engine.sendText(peerNodeId, "hello from Android")
```

Read messages:

```kotlin
val messagesJson = engine.messagesJSON(peerNodeId)
```

Read local node info:

```kotlin
val infoJson = engine.localNodeInfoJSON()
```

## 6. Foreground Service Shape

Android can kill background work. Run the VX6 node inside a foreground service.

```kotlin
class VX6NodeService : Service() {
    private var engine: Engine? = null

    override fun onCreate() {
        super.onCreate()
        startForeground(1001, buildNotification())

        val configPath = File(filesDir, "vx6/config.json").absolutePath
        engine = Mobile.newEngine(configPath)
        engine?.startNode()
    }

    override fun onDestroy() {
        engine?.stopNode()
        engine = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
```

Keep one shared engine owner in the app. For the first MVP, it is acceptable to keep the engine in the service and expose actions through a bound service or app-level controller.

## 7. Compose ViewModel Shape

```kotlin
class ChatViewModel(
    private val engine: Engine
) : ViewModel() {
    var messagesJson by mutableStateOf("[]")
        private set

    fun send(peerNodeId: String, text: String) {
        viewModelScope.launch(Dispatchers.IO) {
            engine.sendText(peerNodeId, text)
            messagesJson = engine.messagesJSON(peerNodeId)
        }
    }

    fun refresh(peerNodeId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            messagesJson = engine.messagesJSON(peerNodeId)
        }
    }
}
```

## 8. MVP Screens

Build these screens first:

1. Setup
   - node name
   - listen address
   - optional advertise address
   - init/start button

2. My Invite
   - show `GenerateChatInvite()`
   - copy/share QR later

3. Add Contact
   - paste invite
   - call `AcceptChatInvite(...)`

4. Chat
   - contact list
   - message list from `MessagesJSON(...)`
   - input box calls `SendText(...)`

5. Status
   - `LocalNodeInfoJSON()`
   - `Logs()`

## 9. Compatibility Notes

The current mobile bridge is compatible with the desktop shared-secret chat path:

- same `vx6chat://invite/...` format
- same DHT conversation key
- same message envelope JSON
- same AES-GCM shared-secret fallback encryption

Next protocol work:

- move desktop X3DH/ratchet session logic into `sdk/chat`
- make desktop `apps/vx6comms` use `sdk/chat`
- add desktop-to-Android integration tests
- add hidden/relay-first invite flow for real mobile networks

## 10. Common Problems

If `GenerateChatInvite()` fails with advertise address error:

- direct invites need a reachable `advertiseAddr`
- for same Wi-Fi testing, set the phone IPv6 address explicitly
- for real mobile networks, prefer hidden/relay invite flow once implemented

If the emulator cannot receive direct connections:

- test with two real devices on the same IPv6-capable Wi-Fi first
- or run one desktop VX6 node as reachable bootstrap/relay

If Android kills the node:

- make sure the foreground service notification is active
- avoid running the node from only an Activity
