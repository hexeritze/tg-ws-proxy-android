package com.amurcanov.tgwsproxy

import android.app.Activity
import android.app.Application
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Looper
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ServiceController
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = Application::class)
class ProxyServiceTest {
    private val controllers = mutableListOf<ServiceController<ProxyService>>()
    private lateinit var context: Context

    @Before fun prepare() {
        context = RuntimeEnvironment.getApplication()
        context.getSharedPreferences("proxy_runtime", Context.MODE_PRIVATE).edit().clear().commit()
    }

    @After fun cleanup() {
        controllers.lastOrNull()?.get()?.onStartCommand(Intent(context, ProxyService::class.java)
            .setAction(ProxyService.ACTION_STOP), 0, 100)
        await { !ProxyService.isRunning.value }
        controllers.forEach { it.destroy() }
    }

    private fun createService(): ProxyService = Robolectric.buildService(ProxyService::class.java)
        .create().also { controllers.add(it) }.get()

    private fun startIntent(port: Int): Intent = Intent(context, ProxyService::class.java)
        .setAction(ProxyService.ACTION_START)
        .putExtra(ProxyService.EXTRA_PORT, port)
        .putExtra(ProxyService.EXTRA_BIND_IP, "127.0.0.1")
        .putExtra(ProxyService.EXTRA_POOL_SIZE, 0)
        .putExtra(ProxyService.EXTRA_CFPROXY_ENABLED, false)
        .putExtra(ProxyService.EXTRA_SECRET_KEY, "0123456789abcdef0123456789abcdef")

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }
    private fun assertListening(port: Int) { Socket("127.0.0.1", port).use { assertTrue(it.isConnected) } }

    private fun await(condition: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        do {
            shadowOf(Looper.getMainLooper()).idle()
            if (condition()) return
            Thread.sleep(10)
        } while (System.nanoTime() < deadline)
        fail("Timed out waiting for proxy lifecycle transition")
    }

    @Test fun finishingActivityAndRemovingTaskLeaveNativeProxyListening() {
        val service = createService()
        val port = freePort()
        assertEquals(Service.START_STICKY, service.onStartCommand(startIntent(port), 0, 1))
        await { ProxyService.isVerifiedRunning.value }
        val activity = Robolectric.buildActivity(Activity::class.java).create().start().resume()
        val logcat = LogManagerTest.BlockedLogcatProcess()
        LogManager.startListening { logcat }
        assertTrue(logcat.reading.await(3, TimeUnit.SECONDS))
        activity.pause().stop().destroy()
        LogManager.stopListening()
        service.onTaskRemoved(Intent(context, Activity::class.java))
        assertTrue(ProxyService.isVerifiedRunning.value)
        assertListening(port)
        assertNotNull(shadowOf(service).lastForegroundNotification)
    }

    @Test fun systemRestartWithNullIntentRestoresSavedSettings() = runBlocking {
        val port = freePort()
        val settings = SettingsStore(context)
        settings.saveAll(
            isDcAuto = true, dc1 = "", dc2 = "", dc3 = "", dc4 = "", dc5 = "", dc203 = "",
            dc1m = "", dc2m = "", dc3m = "", dc4m = "", dc5m = "", dc203m = "",
            isExperimental = false, bindIp = "127.0.0.1", port = port.toString(), poolSize = 0,
            cfproxyEnabled = false, customCfDomainEnabled = false, customCfDomain = "",
            secretKey = "0123456789abcdef0123456789abcdef"
        )
        val original = createService()
        original.onStartCommand(startIntent(port), 0, 1)
        await { ProxyService.isVerifiedRunning.value }
        // Destroy the service instance while preserving durable requested state.
        controllers.removeAt(0).destroy()
        val restored = createService()
        assertEquals(Service.START_STICKY, restored.onStartCommand(null, 0, 2))
        await { ProxyService.isVerifiedRunning.value }
        assertListening(port)
    }

    @Test fun explicitStopPreventsAutomaticRestart() {
        val service = createService()
        val port = freePort()
        service.onStartCommand(startIntent(port), 0, 1)
        await { ProxyService.isVerifiedRunning.value }
        assertEquals(Service.START_NOT_STICKY, service.onStartCommand(Intent(context, ProxyService::class.java)
            .setAction(ProxyService.ACTION_STOP), 0, 2))
        await { !ProxyService.isRunning.value }
        controllers.removeAt(0).destroy()
        val restored = createService()
        assertEquals(Service.START_NOT_STICKY, restored.onStartCommand(null, 0, 3))
        assertTrue(shadowOf(restored).isStoppedBySelf)
        assertFalse(ProxyService.isRunning.value)
    }
}
