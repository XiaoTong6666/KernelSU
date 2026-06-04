package me.weishu.kernelsu.data.model

import androidx.compose.runtime.Immutable

@Immutable
data class KpmModule(
    val name: String,
    val version: String,
    val license: String,
    val author: String,
    val description: String,
    val args: String,
)
