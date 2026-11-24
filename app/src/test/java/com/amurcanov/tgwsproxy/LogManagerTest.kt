package com.amurcanov.tgwsproxy

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.LinkedBlockingQueue
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = android.app.Application::class)
class LogManagerTest {
    @After fun stopReader() { LogManager.stopListening() }

    @Test fun closingBlockedLogcatReaderDoesNotCrashTheProcess() {
        val failures = LinkedBlockingQueue<Throwable>()
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { _, error -> failures.add(error) }
        try {
            repeat(10) {
                val process = BlockedLogcatProcess()
                LogManager.startListening { process }
                assertTrue(process.reading.await(3, TimeUnit.SECONDS))
                LogManager.stopListening()
                assertTrue(process.readerExited.await(3, TimeUnit.SECONDS))
                assertTrue(process.destroyed.await(3, TimeUnit.SECONDS))
            }
            assertNull(failures.poll(300, TimeUnit.MILLISECONDS))
        } finally { Thread.setDefaultUncaughtExceptionHandler(previous) }
    }

    @Test fun unexpectedLogcatExitWhileVisibleDoesNotCrashTheProcess() {
        val failures = LinkedBlockingQueue<Throwable>()
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { _, error -> failures.add(error) }
        try {
            val process = BlockedLogcatProcess()
            LogManager.startListening { process }
            assertTrue(process.reading.await(3, TimeUnit.SECONDS))
            process.destroy()
            assertTrue(process.readerExited.await(3, TimeUnit.SECONDS))
            assertNull(failures.poll(300, TimeUnit.MILLISECONDS))
        } finally { Thread.setDefaultUncaughtExceptionHandler(previous) }
    }

    @Test fun unavailableLogcatDoesNotCrashTheProcess() {
        val failures = LinkedBlockingQueue<Throwable>()
        val attempted = CountDownLatch(1)
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { _, error -> failures.add(error) }
        try {
            LogManager.startListening { attempted.countDown(); throw IOException("logcat unavailable") }
            assertTrue(attempted.await(3, TimeUnit.SECONDS))
            assertNull(failures.poll(300, TimeUnit.MILLISECONDS))
        } finally { Thread.setDefaultUncaughtExceptionHandler(previous) }
    }

    internal class BlockedLogcatProcess : Process() {
        val reading = CountDownLatch(1)
        val readerExited = CountDownLatch(1)
        val destroyed = CountDownLatch(1)
        private val stream = object : InputStream() {
            override fun read(): Int {
                reading.countDown()
                destroyed.await()
                readerExited.countDown()
                throw IOException("stream closed during background transition")
            }
        }
        override fun getInputStream(): InputStream = stream
        override fun getErrorStream(): InputStream = InputStream.nullInputStream()
        override fun getOutputStream(): OutputStream = ByteArrayOutputStream()
        override fun waitFor(): Int { destroyed.await(); return 0 }
        override fun exitValue(): Int = if (destroyed.count == 0L) 0 else throw IllegalThreadStateException()
        override fun destroy() { destroyed.countDown() }
    }
}
