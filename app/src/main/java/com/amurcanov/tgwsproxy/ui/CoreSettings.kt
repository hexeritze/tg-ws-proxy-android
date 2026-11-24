package com.amurcanov.tgwsproxy.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.amurcanov.tgwsproxy.CoreOptions
import com.amurcanov.tgwsproxy.R
import com.amurcanov.tgwsproxy.SettingsStore
import kotlinx.coroutines.launch

@Composable
fun CoreSettings(store: SettingsStore, enabled: Boolean, cfEnabled: Boolean) {
    val options by store.coreOptions.collectAsStateWithLifecycle(initialValue = CoreOptions())
    val scope = rememberCoroutineScope()
    fun save(updated: CoreOptions) { scope.launch { store.saveCoreOptions(updated) } }

    CoreSwitch(stringResource(R.string.core_h2), options.h2,
        enabled && cfEnabled && !options.noSecure && !options.testDc) { save(options.copy(h2 = it)) }
    OutlinedTextField(
        value = options.workers,
        onValueChange = { save(options.copy(workers = it)) },
        label = { Text(stringResource(R.string.core_workers)) },
        modifier = Modifier.fillMaxWidth(), enabled = enabled
    )
    CoreSwitch(stringResource(R.string.core_no_secure), options.noSecure, enabled) { save(options.copy(noSecure = it)) }
    CoreSwitch(stringResource(R.string.core_test_dc), options.testDc, enabled) { save(options.copy(testDc = it)) }
    OutlinedTextField(
        value = options.fakeTlsDomain,
        onValueChange = { value ->
            if (value.all { it.isLetterOrDigit() || it == '.' || it == '-' }) {
                save(options.copy(fakeTlsDomain = value))
            }
        },
        label = { Text(stringResource(R.string.core_fake_tls)) },
        modifier = Modifier.fillMaxWidth(), enabled = enabled, singleLine = true
    )
    CoreSwitch(stringResource(R.string.core_proxy_protocol), options.proxyProtocol, enabled) { save(options.copy(proxyProtocol = it)) }
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth()) {
        Text(stringResource(R.string.core_buffer, options.bufferKb), modifier = Modifier.weight(1f))
        TextButton(onClick = { save(options.copy(bufferKb = (options.bufferKb / 2).coerceAtLeast(4))) },
            enabled = enabled && options.bufferKb > 4) { Text("−") }
        TextButton(onClick = { save(options.copy(bufferKb = (options.bufferKb * 2).coerceAtMost(4096))) },
            enabled = enabled && options.bufferKb < 4096) { Text("+") }
    }
}

@Composable
private fun CoreSwitch(label: String, checked: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, modifier = Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        Switch(checked = checked, onCheckedChange = onChange, enabled = enabled)
    }
}
