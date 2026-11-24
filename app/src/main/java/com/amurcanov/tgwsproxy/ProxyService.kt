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
import android.os.SystemClock
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicLong

class ProxyService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val owner = nextOwner.incrementAndGet()
    private var operation: Job? = null
    private var statsJob: Job? = null
    private var starting = false
    private var stopping = false
    private var lastStart: Intent? = null
    private var lastNotificationContent = ""
    private var lastNotificationAtMs = 0L
    private var notificationStartedAtMs = 0L

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
        const val EXTRA_H2 = "EXTRA_H2"
        const val EXTRA_WORKERS = "EXTRA_WORKERS"
        const val EXTRA_NO_SECURE = "EXTRA_NO_SECURE"
        const val EXTRA_TEST_DC = "EXTRA_TEST_DC"
        const val EXTRA_FAKE_TLS = "EXTRA_FAKE_TLS"
        const val EXTRA_PROXY_PROTOCOL = "EXTRA_PROXY_PROTOCOL"
        const val EXTRA_BUFFER_KB = "EXTRA_BUFFER_KB"
        const val EXTRA_VERBOSE = "EXTRA_VERBOSE"
        private const val NOTIFICATION_ID = 101
        private const val CHANNEL_ID = "TG_WS_Proxy_Service_v4"
        private const val TAG = "ProxyService"
        private val nativeMutex = Mutex()
        private val cleanupScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        private val nextOwner = AtomicLong()
        private var nativeOwner = 0L
        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning
        private val _isVerifiedRunning = MutableStateFlow(false)
        val isVerifiedRunning: StateFlow<Boolean> = _isVerifiedRunning

        private suspend fun stopNative(owner: Long) = nativeMutex.withLock {
            if (nativeOwner == owner) {
                try { NativeProxy.stopProxy() }
                finally { nativeOwner = 0L }
            }
        }

        private fun stopNativeAsync(owner: Long) {
            cleanupScope.launch {
                runCatching { stopNative(owner) }.onFailure { Log.e(TAG, "Native cleanup failed", it) }
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startProxy(intent)
            ACTION_STOP -> stopProxy()
            ACTION_RESTART -> startProxy(lastStart ?: intent, restart = true)
            null -> stopSelf()
        }
        return if (intent?.action == ACTION_STOP) START_NOT_STICKY else START_REDELIVER_INTENT
    }

    private fun startProxy(intent: Intent, restart: Boolean = false) {
        if (stopping || (!restart && (starting || _isRunning.value))) return
        starting = true
        operation?.cancel()
        statsJob?.cancel()
        lastStart = Intent(intent).setAction(ACTION_START)
        notificationStartedAtMs = System.currentTimeMillis()
        val notification = createNotification(getString(R.string.notification_starting))
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else { startForeground(NOTIFICATION_ID, notification) }
        val nativeCacheDir = cacheDir.absolutePath
        operation = serviceScope.launch {
            try {
                val result = withContext(Dispatchers.IO) {
                    nativeMutex.withLock {
                        if (nativeOwner != 0L) NativeProxy.stopProxy()
                        nativeOwner = owner
                        NativeProxy.setPoolSize(intent.getIntExtra(EXTRA_POOL_SIZE, 4))
                        NativeProxy.setBufferSizeKb(intent.getIntExtra(EXTRA_BUFFER_KB, 256))
                        NativeProxy.setCfProxyCacheDir(nativeCacheDir)
                        NativeProxy.setCfProxyConfig(intent.getBooleanExtra(EXTRA_CFPROXY_ENABLED, true), true,
                            intent.getStringExtra(EXTRA_CFPROXY_DOMAIN).orEmpty())
                        NativeProxy.setCfH2Media(intent.getBooleanExtra(EXTRA_H2, true))
                        NativeProxy.setCfWorkerDomains(intent.getStringExtra(EXTRA_WORKERS).orEmpty())
                        NativeProxy.setDisableSecure(intent.getBooleanExtra(EXTRA_NO_SECURE, false))
                        NativeProxy.setForceTestDc(intent.getBooleanExtra(EXTRA_TEST_DC, false))
                        NativeProxy.setFakeTlsDomain(intent.getStringExtra(EXTRA_FAKE_TLS).orEmpty())
                        NativeProxy.setProxyProtocol(intent.getBooleanExtra(EXTRA_PROXY_PROTOCOL, false))
                        NativeProxy.startProxy(intent.getStringExtra(EXTRA_BIND_IP) ?: "127.0.0.1",
                            intent.getIntExtra(EXTRA_PORT, 1443), intent.getStringExtra(EXTRA_IPS).orEmpty(),
                            intent.getStringExtra(EXTRA_SECRET_KEY).orEmpty(),
                            if (intent.getBooleanExtra(EXTRA_VERBOSE, false)) 1 else 0)
                    }
                }
                starting = false
                if (result != 0) {
                    Log.e(TAG, "StartProxy returned $result")
                    stopProxy()
                    return@launch
                }
                updateRunningState(true)
                _isVerifiedRunning.value = true
                updateNotification(getString(R.string.notification_running), force = true)
                startStats()
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (error: Throwable) {
                starting = false
                Log.e(TAG, "Failed to start native proxy", error)
                stopProxy()
            }
        }
    }

    private fun startStats() {
        statsJob = serviceScope.launch {
            var interval = 15_000L
            while (isActive) {
                delay(interval)
                val raw = withContext(Dispatchers.IO) { NativeProxy.getStats() } ?: continue
                val active = extractStat(raw, "active=").toIntOrNull() ?: 0
                val bytes = parseHumanBytes(extractStat(raw, "up=")) + parseHumanBytes(extractStat(raw, "down="))
                updateNotification(getString(R.string.notification_traffic, formatBytes(bytes), active))
                interval = if (active == 0) 60_000L else 15_000L
            }
        }
    }

    private fun stopProxy() {
        if (stopping) return
        stopping = true
        starting = false
        operation?.cancel()
        statsJob?.cancel()
        statsJob = null
        operation = serviceScope.launch {
            updateNotification(getString(R.string.notification_stopping), force = true)
            withContext(Dispatchers.IO) { stopNative(owner) }
            updateRunningState(false)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
            else { @Suppress("DEPRECATION") stopForeground(true) }
            stopSelf()
        }
    }

    private fun updateNotification(content: String, force: Boolean = false) {
        val now = SystemClock.elapsedRealtime()
        if (!force && (lastNotificationContent == content || now - lastNotificationAtMs < 15_000L)) return
        lastNotificationContent = content
        lastNotificationAtMs = now
        val manager = getSystemService(NOTIFICATION_SERVICE) as? NotificationManager
        manager?.notify(NOTIFICATION_ID, createNotification(content))
    }

    private fun updateRunningState(running: Boolean) {
        _isRunning.value = running
        if (!running) _isVerifiedRunning.value = false
        ProxyTileSync.requestSync(this)
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
        val restartIntent = Intent(lastStart ?: Intent(this, ProxyService::class.java)).apply {
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
        serviceScope.cancel()
        stopNativeAsync(owner)
        lastStart = null
        updateRunningState(false)
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}
