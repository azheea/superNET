package app.supernet.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.util.Log

/**
 * The system VPN that gives superNET its TUN device on Android.
 *
 * It only configures the interface (addresses, routes, DNS) and hands the
 * file descriptor to the Rust core, which owns it from then on: closing it
 * there tears the interface down. superNET itself is excluded from the VPN,
 * so its own connections (to nodes, DNS upstreams, the mesh) never loop back.
 *
 * While connected it runs in the foreground with a notification, so the
 * system does not reclaim it when the app is in the background.
 */
class SupernetVpnService : VpnService() {
  companion object {
    const val ACTION_STOP = "app.supernet.client.STOP"
    private const val TAG = "superNET"
    private const val CHANNEL = "vpn"
    private const val NOTIFICATION_ID = 1

    /** Called once with (fd, null) or (null, error) after an establish request. */
    @Volatile var pending: ((Int?, String?) -> Unit)? = null
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    if (intent == null || intent.action == ACTION_STOP) {
      shutdown()
      return START_NOT_STICKY
    }
    val done = pending
    pending = null
    try {
      val b = Builder()
        .setSession("superNET")
        .setMtu(intent.getIntExtra("mtu", 1500))
        .addAddress("172.19.0.1", 30)
        .addRoute("0.0.0.0", 0)
        .addDnsServer("172.19.0.2")
        // IPv6 is captured too, so it cannot leak around the rules.
        .addAddress("fdfe:dcba:9876::1", 126)
        .addRoute("::", 0)
        .addDnsServer("fdfe:dcba:9876::2")
        .addDisallowedApplication(packageName)
      val meshIp = intent.getStringExtra("meshIp")
      meshIp?.let { b.addAddress(it, intent.getIntExtra("meshPrefix", 24)) }
      if (Build.VERSION.SDK_INT >= 29) b.setMetered(false)
      val pfd = b.establish() ?: throw IllegalStateException("没有 VPN 授权")
      goForeground(meshIp)
      done?.invoke(pfd.detachFd(), null)
    } catch (e: Exception) {
      Log.e(TAG, "establish failed", e)
      done?.invoke(null, e.message ?: e.toString())
      shutdown()
    }
    return START_NOT_STICKY
  }

  private fun goForeground(meshIp: String?) {
    val nm = getSystemService(NotificationManager::class.java)
    if (Build.VERSION.SDK_INT >= 26) {
      nm.createNotificationChannel(NotificationChannel(CHANNEL, "VPN 状态", NotificationManager.IMPORTANCE_LOW))
    }
    val open = PendingIntent.getActivity(
      this, 0, Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
      PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
    )
    val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL) else @Suppress("DEPRECATION") Notification.Builder(this)
    val notification = builder
      .setSmallIcon(R.drawable.ic_stat_supernet)
      .setContentTitle("superNET 已连接")
      .setContentText(if (meshIp != null) "按规则分流 · 组网地址 $meshIp" else "按规则分流")
      .setContentIntent(open)
      .setOngoing(true)
      .build()
    if (Build.VERSION.SDK_INT >= 34) {
      startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
    } else {
      startForeground(NOTIFICATION_ID, notification)
    }
  }

  private fun shutdown() {
    if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE) else @Suppress("DEPRECATION") stopForeground(true)
    stopSelf()
  }

  override fun onRevoke() {
    // Another VPN took over or the user turned it off in system settings.
    Log.i(TAG, "VPN revoked")
    shutdown()
  }
}
