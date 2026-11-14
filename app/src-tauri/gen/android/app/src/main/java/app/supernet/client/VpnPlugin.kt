package app.supernet.client

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class EstablishArgs {
  var mtu: Int = 1500
  var meshIp: String? = null
  var meshPrefix: Int = 24
}

/** Called from the Rust core (not from the web UI). */
@TauriPlugin
class VpnPlugin(private val activity: Activity) : Plugin(activity) {
  /** Ask for VPN permission if the user has not granted it yet. */
  @Command
  fun prepare(invoke: Invoke) {
    val intent = VpnService.prepare(activity)
    if (intent == null) {
      invoke.resolve(JSObject().apply { put("granted", true) })
    } else {
      startActivityForResult(invoke, intent, "consentResult")
    }
  }

  @ActivityCallback
  fun consentResult(invoke: Invoke, result: ActivityResult) {
    invoke.resolve(JSObject().apply { put("granted", result.resultCode == Activity.RESULT_OK) })
  }

  /** Start the VPN; resolves with the TUN file descriptor, now owned by the caller. */
  @Command
  fun establish(invoke: Invoke) {
    val args = invoke.parseArgs(EstablishArgs::class.java)
    SupernetVpnService.pending = { fd, error ->
      if (fd != null) {
        invoke.resolve(JSObject().apply { put("fd", fd) })
      } else {
        invoke.reject(error ?: "VPN 启动失败")
      }
    }
    val intent = Intent(activity, SupernetVpnService::class.java).apply {
      putExtra("mtu", args.mtu)
      args.meshIp?.let { putExtra("meshIp", it) }
      putExtra("meshPrefix", args.meshPrefix)
    }
    activity.startService(intent)
  }

  @Command
  fun stop(invoke: Invoke) {
    activity.startService(Intent(activity, SupernetVpnService::class.java).setAction(SupernetVpnService.ACTION_STOP))
    invoke.resolve()
  }
}
