package com.amurcanov.tgwsproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import android.widget.Toast
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.time.Duration.Companion.milliseconds
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket

class ProxyService : Service() {

    private var wakeLock: PowerManager.WakeLock? = null
    private var statsJob: Job? = null
    private var restartJob: Job? = null
    private var lastNotificationContent: String = ""
    private var lastNotificationAtMs: Long = 0L
    private var notificationStartedAtMs: Long = 0L
    @Volatile
    private var stopInProgress = false
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Saved intent extras for restart on kill / onTaskRemoved
    private var lastBindIp: String = "127.0.0.1"
    private var lastPort: Int = 1443
    private var lastIps: String = ""
    private var lastPoolSize: Int = 4
    private var lastCfEnabled: Boolean = true
    private var lastCfPriority: Boolean = true
    private var lastCfDomain: String = ""
    private var lastSecretKey: String = ""

    private enum class ProxyLifecycleState {
        STOPPED,
        STARTING,
        RUNNING,
        STOPPING,
        FAILED
    }
    private val lifecycleMutex = Mutex()

    @Volatile
    private var lifecycleState = ProxyLifecycleState.STOPPED
    private var latestStartId: Int = 0


    companion object {
        const val ACTION_START = "com.amurcanov.tgwsproxy.START"
        const val ACTION_STOP = "com.amurcanov.tgwsproxy.STOP"
        const val ACTION_RESTART = "com.amurcanov.tgwsproxy.RESTART"
        const val EXTRA_BIND_IP = "EXTRA_BIND_IP"
        const val EXTRA_PORT = "EXTRA_PORT"
        const val EXTRA_IPS = "EXTRA_IPS"
        const val EXTRA_POOL_SIZE = "EXTRA_POOL_SIZE"
        const val EXTRA_CFPROXY_ENABLED = "EXTRA_CFPROXY_ENABLED"
        const val EXTRA_CFPROXY_PRIORITY = "EXTRA_CFPROXY_PRIORITY"
        const val EXTRA_CFPROXY_DOMAIN = "EXTRA_CFPROXY_DOMAIN"
        const val EXTRA_SECRET_KEY = "EXTRA_SECRET_KEY"
        
        private const val NOTIFICATION_ID = 101
        private const val CHANNEL_ID = "TG_WS_Proxy_Service_v4"
        private const val TAG = "ProxyService"

        // Wakelock refresh interval (25 min, re-acquire before 30-min timeout)
        private const val WAKELOCK_TIMEOUT_MS = 30L * 60 * 1000
        private const val WAKELOCK_REFRESH_MS = 25L * 60 * 1000

        // Stats/notification update interval
        private const val STATS_UPDATE_MS = 3_000L
        private const val NOTIFICATION_MIN_UPDATE_MS = 3_000L

        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning
        private val _isVerifiedRunning = MutableStateFlow(false)
        val isVerifiedRunning: StateFlow<Boolean> = _isVerifiedRunning
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        latestStartId  = startId
        when (intent?.action) {
            ACTION_START -> {
                LogManager.clearLogs()
                val bindIp = intent.getStringExtra(EXTRA_BIND_IP) ?: "127.0.0.1"
                val port = intent.getIntExtra(EXTRA_PORT, 1443)
                val ips = intent.getStringExtra(EXTRA_IPS) ?: ""
                val poolSize = intent.getIntExtra(EXTRA_POOL_SIZE, 4)
                val cfEnabled = intent.getBooleanExtra(EXTRA_CFPROXY_ENABLED, true)
                val cfPriority = intent.getBooleanExtra(EXTRA_CFPROXY_PRIORITY, true)
                val cfDomain = intent.getStringExtra(EXTRA_CFPROXY_DOMAIN) ?: ""
                val secretKey = intent.getStringExtra(EXTRA_SECRET_KEY) ?: ""
                startProxy(bindIp, port, ips, poolSize, cfEnabled, cfPriority, cfDomain, secretKey)
            }
            ACTION_STOP -> {
                stopProxy()
            }
            ACTION_RESTART -> {
                restartProxy()
            }
            null -> {
                // Service restarted by system after being killed (START_REDELIVER_INTENT)
                // If we had saved params, try to restart
                if (lastPort > 0 && lastSecretKey.isNotEmpty()) {
                    Log.w(TAG, "Service restarted by system, re-starting proxy")
                    startProxy(lastBindIp, lastPort, lastIps, lastPoolSize, lastCfEnabled, lastCfPriority, lastCfDomain, lastSecretKey)
                } else {
                    stopSelf()
                }
            }
        }
        // START_REDELIVER_INTENT: if the system kills the service, it will restart it
        // and re-deliver the last intent, so we don't lose the config.
        return START_REDELIVER_INTENT
    }

    private fun isPortAvailable(bindIp: String, port: Int): Boolean {
        return try {
            ServerSocket().use { socket ->
                socket.reuseAddress = true
                socket.bind(InetSocketAddress(InetAddress.getByName(bindIp), port))
                true
            }
        } catch (_: Exception) {
            // (Если надо, то тут может быть IOException или SecurityException) (IOException добавляет новый import так что "_", по-моему, лучше)
            return false
        }
    }


    private fun startProxy(
        bindIp: String,
        port: Int,
        ips: String,
        poolSize: Int = 4,
        cfEnabled: Boolean = true,
        cfPriority: Boolean = true,
        cfDomain: String = "",
        secretKey: String = ""
    ) {
        serviceScope.launch(Dispatchers.Main.immediate) {
            lifecycleMutex.withLock {
                startProxyLocked(
                    bindIp, port, ips, poolSize,
                    cfEnabled, cfPriority, cfDomain, secretKey
                )
            }
        }
    }

    // Must only be called while lifecycleMutex is held.
    private suspend fun startProxyLocked(
        bindIp: String,
        port: Int,
        ips: String,
        poolSize: Int,
        cfEnabled: Boolean,
        cfPriority: Boolean,
        cfDomain: String,
        secretKey: String
    ) {
        if (lifecycleState == ProxyLifecycleState.RUNNING ||
            lifecycleState == ProxyLifecycleState.STARTING ||
            lifecycleState == ProxyLifecycleState.STOPPING
        ) {
            Log.i(TAG, "Ignoring START while proxy state is $lifecycleState")
            return
        }

        try {
            // A previous failed operation may have left native state behind.
            if (lifecycleState == ProxyLifecycleState.FAILED) {
                val cleanupResult = withContext(Dispatchers.IO) {
                    NativeProxy.stopProxy()
                }
                if (cleanupResult != 0 && cleanupResult != -1) {
                    Log.e(TAG, "Cannot clear failed native state: $cleanupResult")
                    updateNotification(
                        getString(R.string.notification_error, "Native cleanup failed: $cleanupResult"),
                        force = true
                    )
                    return
                }
                updateRunningState(false)
                lifecycleState = ProxyLifecycleState.STOPPED
            }

            lifecycleState = ProxyLifecycleState.STARTING
            stopInProgress = false
            _isVerifiedRunning.value = false

            // Save params for restart
            lastBindIp = bindIp
            lastPort = port
            lastIps = ips
            lastPoolSize = poolSize
            lastCfEnabled = cfEnabled
            lastCfPriority = cfPriority
            lastCfDomain = cfDomain
            lastSecretKey = secretKey

            notificationStartedAtMs = System.currentTimeMillis()
            lastNotificationContent = getString(R.string.notification_starting)
            lastNotificationAtMs = notificationStartedAtMs
            val notification = createNotification(lastNotificationContent)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            acquireWakeLock()

            val canObtainPort = withContext(Dispatchers.IO) {
                isPortAvailable(bindIp, port)
            }
            if (!canObtainPort) {
                val message = getString(R.string.port_is_not_available, port)
                lifecycleState = ProxyLifecycleState.FAILED
                updateNotification(message, force = true)
                Toast.makeText(this@ProxyService, message, Toast.LENGTH_SHORT).show()
                releaseWakeLock()
                return
            }

            // JNA calls are blocking: keep them off the main thread, but inside
            // the lifecycle lock so STOP/RESTART cannot overlap START.
            val result = withContext(Dispatchers.IO) {
                NativeProxy.setPoolSize(poolSize)
                NativeProxy.setCfProxyCacheDir(cacheDir.absolutePath)
                NativeProxy.setCfProxyConfig(cfEnabled, cfPriority, cfDomain)
                NativeProxy.startProxy(bindIp, port, ips, secretKey, 1)
            }

            if (result != 0) {
                lifecycleState = ProxyLifecycleState.FAILED
                stopInProgress = false
                Log.e(TAG, "StartProxy returned error code: $result")
                updateNotification(
                    getString(R.string.notification_start_error_code, result),
                    force = true
                )
                releaseWakeLock()
                return
            }

            lifecycleState = ProxyLifecycleState.RUNNING
            updateRunningState(true)
            _isVerifiedRunning.value = true
            updateNotification(getString(R.string.notification_running), force = true)
            Log.i(TAG, "Proxy ready: listening on port $port")

            // Stats updater. Kept separate from lifecycle operations.
            statsJob?.cancel()
            statsJob = serviceScope.launch {
                launch {
                    while (isActive) {
                        delay(WAKELOCK_REFRESH_MS)
                        refreshWakeLock()
                    }
                }
                while (isActive) {
                    delay(STATS_UPDATE_MS)
                    if (lifecycleState == ProxyLifecycleState.RUNNING && !stopInProgress) {
                        try {
                            val rawStats = NativeProxy.getStats() ?: continue
                            val upRaw = extractStat(rawStats, "up=")
                            val downRaw = extractStat(rawStats, "down=")
                            val activeConns = extractStat(rawStats, "active=")
                            val totalBytes = parseHumanBytes(upRaw) + parseHumanBytes(downRaw)
                            val active = activeConns.toIntOrNull() ?: 0
                            val text = getString(
                                R.string.notification_traffic,
                                formatBytes(totalBytes),
                                active
                            )
                            updateNotification(text)
                        } catch (e: Exception) {
                            Log.w(TAG, "Stats update failed", e)
                        }
                    }
                }
            }
        } catch (e: CancellationException) {
            lifecycleState = ProxyLifecycleState.FAILED
            stopInProgress = false
            releaseWakeLock()
            throw e
        } catch (e: Throwable) {
            lifecycleState = ProxyLifecycleState.FAILED
            stopInProgress = false
            Log.e(TAG, "Failed to start proxy", e)
            updateNotification(
                getString(R.string.notification_error, e.message ?: "Unknown error"),
                force = true
            )
            releaseWakeLock()
            updateRunningState(false)
        }
    }

    private fun updateNotification(content: String, force: Boolean = false) {
        val now = System.currentTimeMillis()
        if (!force) {
            if (content == lastNotificationContent) return
            if (lastNotificationAtMs != 0L && now - lastNotificationAtMs < NOTIFICATION_MIN_UPDATE_MS) return
        }

        lastNotificationContent = content
        lastNotificationAtMs = now
        try {
            val manager = getSystemService(NOTIFICATION_SERVICE) as? NotificationManager
            manager?.notify(NOTIFICATION_ID, createNotification(content))
        } catch (e: Exception) {
            Log.w(TAG, "Failed to update notification", e)
        }
    }

    private fun restartProxy() {
        if (restartJob?.isActive == true) return

        restartJob = serviceScope.launch(Dispatchers.Main.immediate) {
            lifecycleMutex.withLock {
                if (lastPort <= 0 || lastSecretKey.isEmpty()) {
                    Log.w(TAG, "Restart requested without saved proxy configuration")
                    return@withLock
                }

                Log.i(TAG, "Restarting proxy from notification")
                updateNotification(getString(R.string.notification_restarting), force = true)

                if (!stopProxyLocked(reason = "restart", stopService = false)) {
                    Log.e(TAG, "Restart aborted: native proxy did not stop cleanly")
                    return@withLock
                }

                // StopProxy() has returned, so the native listener and tasks have
                // completed their shutdown. No arbitrary delay is necessary.
                startProxyLocked(
                    bindIp = lastBindIp,
                    port = lastPort,
                    ips = lastIps,
                    poolSize = lastPoolSize,
                    cfEnabled = lastCfEnabled,
                    cfPriority = lastCfPriority,
                    cfDomain = lastCfDomain,
                    secretKey = lastSecretKey
                )
            }
        }
    }

    private fun extractStat(stats: String, key: String): String {
        val idx = stats.indexOf(key)
        if (idx == -1) return "0B"
        val start = idx + key.length
        val end = stats.indexOf(" ", start)
        return if (end == -1) stats.substring(start) else stats.substring(start, end)
    }
    
    private fun parseHumanBytes(s: String): Double {
        val num = s.replace(Regex("[^0-9.]"), "").toDoubleOrNull() ?: 0.0
        return when {
            s.endsWith("TB") -> num * 1024.0 * 1024 * 1024 * 1024
            s.endsWith("GB") -> num * 1024.0 * 1024 * 1024
            s.endsWith("MB") -> num * 1024.0 * 1024
            s.endsWith("KB") -> num * 1024.0
            else -> num
        }
    }
    
    private fun formatBytes(bytes: Double): String {
        if (bytes < 1024) return "%.0fB".format(bytes)
        if (bytes < 1024 * 1024) return "%.1fKB".format(bytes / 1024)
        if (bytes < 1024 * 1024 * 1024) return "%.1fMB".format(bytes / (1024 * 1024))
        return "%.2fGB".format(bytes / (1024 * 1024 * 1024))
    }

    private fun stopProxy() {
        serviceScope.launch(Dispatchers.Main.immediate) {
            lifecycleMutex.withLock {
                stopProxyLocked(reason = "stop", stopService = true)
            }
        }
    }

    // Must only be called while lifecycleMutex is held.
    // StopProxy returns 0 on success and -1 if there was no native instance.
    private suspend fun stopProxyLocked(reason: String, stopService: Boolean): Boolean {
        lifecycleState = ProxyLifecycleState.STOPPING
        stopInProgress = true
        statsJob?.cancel()
        statsJob = null
        updateNotification(getString(R.string.notification_stopping), force = true)

        val result = try {
            withContext(Dispatchers.IO) {
                NativeProxy.stopProxy()
            }
        } catch (e: CancellationException) {
            lifecycleState = ProxyLifecycleState.FAILED
            stopInProgress = false
            throw e
        } catch (e: Throwable) {
            Log.e(TAG, "StopProxy failed during $reason", e)
            lifecycleState = ProxyLifecycleState.FAILED
            stopInProgress = false
            updateNotification(
                getString(R.string.notification_error, e.message ?: "Stop failed"),
                force = true
            )
            return false
        }

        if (result != 0 && result != -1) {
            Log.e(TAG, "StopProxy returned error code $result during $reason")
            lifecycleState = ProxyLifecycleState.FAILED
            stopInProgress = false
            updateNotification(
                getString(R.string.notification_error, "StopProxy returned $result"),
                force = true
            )
            return false
        }

        lifecycleState = ProxyLifecycleState.STOPPED
        stopInProgress = false
        releaseWakeLock()
        updateRunningState(false)

        if (stopService && stopSelfResult(latestStartId)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        }
        return true
    }

    /**
     * Called when the user swipes the app from recents.
     * Without this, the service would be killed on many OEM Androids.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        if (_isRunning.value) {
            Log.w(TAG, "onTaskRemoved: proxy is running, service stays alive")
            // The service continues because stopWithTask=false in manifest
            // No action needed — the service keeps running.
        }
    }

    private fun acquireWakeLock() {
        try {
            val powerManager = getSystemService(POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "TgWsProxy::ServiceWakeLock"
            ).apply {
                // Acquire with timeout. System may ignore indefinite wakelocks.
                acquire(WAKELOCK_TIMEOUT_MS)
            }
            Log.d(TAG, "WakeLock acquired (${WAKELOCK_TIMEOUT_MS / 60000}min)")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to acquire WakeLock", e)
        }
    }

    /**
     * Periodically refresh wakelock to prevent system from expiring it.
     */
    private fun refreshWakeLock() {
        try {
            wakeLock?.let {
                if (it.isHeld) {
                    it.release()
                }
            }
            val powerManager = getSystemService(POWER_SERVICE) as PowerManager
            wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "TgWsProxy::ServiceWakeLock"
            ).apply {
                acquire(WAKELOCK_TIMEOUT_MS)
            }
            Log.d(TAG, "WakeLock refreshed")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to refresh WakeLock", e)
        }
    }

    private fun releaseWakeLock() {
        try {
            wakeLock?.let {
                if (it.isHeld) {
                    it.release()
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to release WakeLock", e)
        }
        wakeLock = null
    }

    private fun updateRunningState(isRunning: Boolean) {
        _isRunning.value = isRunning
        if (!isRunning) {
            _isVerifiedRunning.value = false
        }
        ProxyTileService.requestSync(this)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_description)
                setShowBadge(false)
                setSound(null, null)
                enableVibration(false)
                enableLights(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
            val manager = getSystemService(NOTIFICATION_SERVICE) as? NotificationManager
            manager?.createNotificationChannel(serviceChannel)
        }
    }

    private fun createNotification(content: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPendingIntent = PendingIntent.getActivity(
            this, 1, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, ProxyService::class.java).apply {
            action = ACTION_STOP
        }
        val restartIntent = Intent(this, ProxyService::class.java).apply {
            action = ACTION_RESTART
        }
        val restartPendingIntent = PendingIntent.getService(
            this, 2, restartIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Telegram WS Proxy")
            .setContentText(content)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(openPendingIntent) // Tap notification → open app
            .addAction(android.R.drawable.ic_popup_sync, getString(R.string.notification_restart), restartPendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, getString(R.string.notification_disconnect), stopPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setWhen(notificationStartedAtMs.takeIf { it > 0L } ?: System.currentTimeMillis())
            .setShowWhen(false)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    override fun onDestroy() {
        restartJob?.cancel()
        restartJob = null
        statsJob?.cancel()
        statsJob = null
        releaseWakeLock()
        if (_isRunning.value) {
            updateRunningState(false)
        }
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }
}
