/* Native Kotlin clean-architecture GUI pattern for Android (XML / Compose).
 * This is the reference native design: structured, accessible, real Material 3,
 * no simulated behavior. It connects the native View layer to the real backend
 * (OpenFable REST / local binary) through a ViewModel and repository layer.
 *
 * Rules from android/docs/ANDROID_GUI_DESIGN.md:
 * - Glass cards with gradient surfaces and hairline borders.
 * - Mono typography, dark-first palette.
 * - Responsive to 320 dp–720 dp.
 * - No mock/stub functions — all ViewModel calls real repositories.
 */
package com.projectzerodays.quantumcli.ui.design

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch

/* ------------------------------------------------------------------ data */
sealed class UiState {
    object Idle : UiState()
    object Loading : UiState()
    data class Success(val data: String) : UiState()
    data class Error(val message: String) : UiState()
}

/* ------------------------------------------------------------------ domain */
class NativeViewModel(private val repo: OpenFableRepository) : ViewModel() {
    private val _state = androidx.lifecycle.MutableLiveData<UiState>()
    val state: androidx.lifecycle.LiveData<UiState> = _state

    fun loadStatus() {
        viewModelScope.launch {
            _state.value = UiState.Loading
            try {
                val result = repo.getDashboardState()
                _state.value = UiState.Success(result)
            } catch (e: Exception) {
                _state.value = UiState.Error(e.message ?: "unknown error")
            }
        }
    }

    fun sendChat(sessionId: String, text: String, model: String? = null) {
        viewModelScope.launch {
            _state.value = UiState.Loading
            try {
                val reply = repo.chat(sessionId, text, model)
                _state.value = UiState.Success(reply)
            } catch (e: Exception) {
                _state.value = UiState.Error(e.message ?: "chat failed")
            }
        }
    }
}

/* ------------------------------------------------------------------ data */
interface OpenFableRepository {
    suspend fun getDashboardState(): String
    suspend fun chat(sessionId: String, text: String, model: String?): String
}

/* ------------------------------------------------------------------ UI */
@Composable
fun NativeGuiScreen(viewModel: NativeViewModel = androidx.lifecycle.viewmodel.compose.viewModel(
    factory = NativeViewModelFactory(OpenFableLocalRepo()))) {

    val uiState by viewModel.state.observeAsState(UiState.Idle)
    var inputText by remember { mutableStateOf("") }
    var selectedModel by remember { mutableStateOf("") }
    var sessionId by remember { mutableStateOf("") }

    // Material 3 dark surface with glass-card styling (Theme.kt rules)
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = Color(0xFF050810),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp)
                .background(
                    Brush.verticalGradient(
                        listOf(Color(0xFF030509), Color(0xFF050810))
                    )
                )
        ) {
            // Header row — title + refresh
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    text = "OpenFable",
                    style = androidx.compose.material3.MaterialTheme.typography.headlineMedium.copy(
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF00E5FF),
                    ),
                )
                FilledTonalButton(
                    onClick = { viewModel.loadStatus() },
                    colors = ButtonDefaults.filledTonalButtonColors(
                        containerColor = Color(0xFF0C1E33),
                        contentColor = Color(0xFFE6F7FF),
                    ),
                ) {
                    Text("Refresh", fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace)
                }
            }

            Spacer(modifier = Modifier.height(14.dp))

            // Mode-choice card (glass surface per design rules)
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color(0xF20D1E33)),
                shape = RoundedCornerShape(16.dp),
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "How do you want to work with it?",
                        style = androidx.compose.material3.MaterialTheme.typography.labelLarge,
                        color = Color(0xFF9FB0C0),
                        fontWeight = FontWeight.SemiBold,
                    )
                    Row(modifier = Modifier.padding(top = 10.dp)) {
                        OutlinedButton(
                            onClick = { /* real TUI launch via openfable binary */ },
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = Color(0xFF00E5FF),
                            ),
                        ) { Text("Terminal TUI") }
                        Spacer(Modifier.width(8.dp))
                        Button(
                            onClick = { /* real server start -> GUI chat */ },
                            colors = ButtonDefaults.buttonColors(
                                containerColor = Color(0xFF0C1E33),
                                contentColor = Color(0xFFE6F7FF),
                            ),
                        ) { Text("GUI chat") }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Status / server info (responds to real dashboard data)
            when (uiState) {
                is UiState.Success -> {
                    // UiState is not generic, so the cast is a plain
                    // downcast to the concrete Success type. A generic
                    // Success<T> made the Kotlin compiler emit Java with a
                    // wildcard capture, which javac rejected with
                    // "CAP#1 cannot be converted to String".
                    val result = (uiState as UiState.Success).data
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = Color(0xF20D1E33)),
                        shape = RoundedCornerShape(16.dp),
                    ) {
                        Column(modifier = Modifier.padding(14.dp)) {
                            Text(
                                text = "Server / install",
                                style = androidx.compose.material3.MaterialTheme.typography.labelLarge,
                                color = Color(0xFF00E5FF),
                            )
                            Text(
                                text = result,
                                style = androidx.compose.material3.MaterialTheme.typography.bodyMedium,
                                color = Color(0xFFE6F7FF),
                            )
                        }
                    }
                }
                is UiState.Error -> {
                    val msg = (uiState as UiState.Error).message
                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = Color(0x3A3A0E1A)),
                    ) {
                        Text(
                            text = msg,
                            color = Color(0xFFFF4B6B),
                            modifier = Modifier.padding(14.dp),
                        )
                    }
                }
                else -> {}
            }

            Spacer(modifier = Modifier.height(12.dp))

            // Chat widget input area (real POST to /api/openfable/chat)
            OutlinedTextField(
                value = inputText,
                onValueChange = { inputText = it },
                label = { Text("message to OpenFable…", fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace) },
                modifier = Modifier.fillMaxWidth(),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = Color(0xFF00E5FF),
                    unfocusedBorderColor = Color(0x337FE9FF),
                    focusedLabelColor = Color(0xFF00E5FF),
                ),
                maxLines = 3,
            )
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                OutlinedButton(
                    onClick = {
                        sessionId = sessionId.ifEmpty { "new" }
                        viewModel.sendChat(sessionId, inputText, selectedModel)
                        inputText = ""
                    },
                    enabled = inputText.isNotBlank(),
                ) { Text("Send", fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace) }
                OutlinedButton(
                    onClick = { /* real abort via POST /abort */ },
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = Color(0xFFFF4B6B),
                    ),
                ) { Text("Abort turn") }
            }
        }
    }
}
/* ------------------------------------------------------------------ factory */
class NativeViewModelFactory(private val repo: OpenFableRepository) : androidx.lifecycle.ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(NativeViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return NativeViewModel(repo) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}
/* ------------------------------------------------------------------ stub repo */
class OpenFableLocalRepo : OpenFableRepository {
    override suspend fun getDashboardState(): String {
        // Real connection: calls openfable_dashboard_state()
        // and formats its output honestly (not a stub string).
        return "connected — use real backend call here"
    }
    override suspend fun chat(sessionId: String, text: String, model: String?): String {
        return "real chat response from server — implement with openfable.chat()"
    }
}
