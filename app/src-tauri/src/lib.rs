//! Tauri side of the superNET app: the window and the commands the UI calls.
//! What the commands do lives in `supernet-control`, shared with the headless
//! web console (`supernet --web`).

use std::path::PathBuf;
use std::sync::Arc;

use supernet_control::{Controller, Exported, MeshView, Options, Overview, Res, Settings};
use supernet_core::engine::{RouteInfo, Status};
use supernet_core::stats::{ConnInfo, LogLine};
use supernet_core::Mode;
use tauri::{Manager, RunEvent, State};

#[cfg(target_os = "android")]
mod android;

type App = Controller;

#[tauri::command]
async fn overview(app: State<'_, Arc<App>>) -> Res<Overview> {
    app.overview().await
}

#[tauri::command]
async fn connect(app: State<'_, Arc<App>>) -> Res<Status> {
    app.connect_cmd().await
}

#[tauri::command]
async fn disconnect(app: State<'_, Arc<App>>) -> Res<Status> {
    app.disconnect().await
}

#[tauri::command]
async fn set_tun(app: State<'_, Arc<App>>, enabled: bool) -> Res<()> {
    app.set_tun(enabled).await
}

#[tauri::command]
async fn mesh_status(app: State<'_, Arc<App>>) -> Res<MeshView> {
    app.mesh_status().await
}

#[tauri::command]
async fn mesh_join(app: State<'_, Arc<App>>, link: String, name: String) -> Res<()> {
    app.mesh_join(link, name).await
}

#[tauri::command]
async fn mesh_update(app: State<'_, Arc<App>>, enabled: bool, relay: bool, name: String) -> Res<()> {
    app.mesh_update(enabled, relay, name).await
}

#[tauri::command]
async fn mesh_leave(app: State<'_, Arc<App>>) -> Res<()> {
    app.mesh_leave().await
}

/// Start an elevated copy of the app (same data folder), then exit.
#[tauri::command]
async fn restart_as_admin(app: State<'_, Arc<App>>, handle: tauri::AppHandle) -> Res<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let exe = std::env::current_exe().map_err(supernet_control::fail)?;
        let wide = |s: &std::ffi::OsStr| s.encode_wide().chain(Some(0)).collect::<Vec<u16>>();
        let args = format!("--data-dir \"{}\"", app.data_dir().display());
        let (verb, file, params) = (wide("runas".as_ref()), wide(exe.as_os_str()), wide(args.as_ref()));
        // SAFETY: null-terminated UTF-16 strings that outlive the call.
        let rc = unsafe {
            windows_sys::Win32::UI::Shell::ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                params.as_ptr(),
                std::ptr::null(),
                windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
            )
        };
        if (rc as isize) <= 32 {
            return Err("没有以管理员身份启动（可能取消了系统提示）".into());
        }
        app.shutdown().await;
        handle.exit(0);
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = (app, handle);
        Err("这个平台暂不支持".into())
    }
}

#[tauri::command]
async fn set_mode(app: State<'_, Arc<App>>, mode: Mode) -> Res<()> {
    app.set_mode(mode).await
}

#[tauri::command]
async fn set_system_proxy(app: State<'_, Arc<App>>, enabled: bool) -> Res<()> {
    app.set_system_proxy(enabled).await
}

#[tauri::command]
async fn select_node(app: State<'_, Arc<App>>, group: String, node: String) -> Res<()> {
    app.select_node(group, node).await
}

#[tauri::command]
async fn import_node(app: State<'_, Arc<App>>, text: String, name: String) -> Res<String> {
    app.import_node(text, name).await
}

#[tauri::command]
async fn remove_node(app: State<'_, Arc<App>>, name: String) -> Res<()> {
    app.remove_node(name).await
}

#[tauri::command]
async fn export_node(app: State<'_, Arc<App>>, name: String) -> Res<Exported> {
    app.export_node(name).await
}

#[tauri::command]
async fn probe_node(app: State<'_, Arc<App>>, name: String) -> Res<u64> {
    app.probe_node(name).await
}

#[tauri::command]
async fn get_rules(app: State<'_, Arc<App>>) -> Res<String> {
    app.get_rules().await
}

#[tauri::command]
async fn save_rules(app: State<'_, Arc<App>>, text: String) -> Res<Vec<String>> {
    app.save_rules(text).await
}

#[tauri::command]
async fn explain(app: State<'_, Arc<App>>, target: String) -> Res<RouteInfo> {
    app.explain(target).await
}

#[tauri::command]
fn connections(app: State<'_, Arc<App>>) -> Vec<ConnInfo> {
    app.connections()
}

#[tauri::command]
fn close_connection(app: State<'_, Arc<App>>, id: u64) -> bool {
    app.close_connection(id)
}

#[tauri::command]
fn logs(app: State<'_, Arc<App>>, after: u64) -> Vec<LogLine> {
    app.logs(after)
}

#[tauri::command]
async fn get_settings(app: State<'_, Arc<App>>) -> Res<Settings> {
    app.get_settings().await
}

#[tauri::command]
async fn save_settings(app: State<'_, Arc<App>>, settings: Settings) -> Res<Vec<String>> {
    app.save_settings(settings).await
}

/// `--data-dir DIR` or `SUPERNET_DATA_DIR` override where the profile lives
/// (tests, and the elevated restart, which does not inherit the environment).
fn data_dir(handle: &tauri::AppHandle) -> anyhow::Result<PathBuf> {
    let mut args = std::env::args();
    while let Some(a) = args.next() {
        if a == "--data-dir" {
            if let Some(dir) = args.next() {
                return Ok(PathBuf::from(dir));
            }
        }
    }
    if let Some(dir) = std::env::var_os("SUPERNET_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    Ok(handle.path().app_data_dir()?)
}

fn setup(handle: &tauri::AppHandle) -> anyhow::Result<()> {
    let dir = data_dir(handle)?;
    #[cfg(target_os = "android")]
    let vpn: Option<Arc<dyn supernet_control::Vpn>> = Some(Arc::new(android::AndroidVpn));
    #[cfg(not(target_os = "android"))]
    let vpn = None;
    let app = Controller::open(Options { profile_path: dir.join("profile.yaml"), data_dir: dir, vpn, mesh_only: false, force_tun: false })?;
    handle.manage(app.clone());
    if app.engine.profile().auto_connect {
        tauri::async_runtime::spawn(async move {
            if let Err(e) = app.connect().await {
                app.set_warnings(vec![format!("自动连接失败：{e}")]);
            }
        });
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(target_os = "android")]
    let builder = builder.plugin(android::init());
    builder
        .setup(|app| {
            setup(app.handle()).map_err(|e| -> Box<dyn std::error::Error> { format!("{e:#}").into() })?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            overview,
            connect,
            disconnect,
            set_tun,
            restart_as_admin,
            mesh_status,
            mesh_join,
            mesh_update,
            mesh_leave,
            set_mode,
            set_system_proxy,
            select_node,
            import_node,
            remove_node,
            export_node,
            probe_node,
            get_rules,
            save_rules,
            explain,
            connections,
            close_connection,
            logs,
            get_settings,
            save_settings,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the superNET app")
        .run(|handle, event| {
            if let RunEvent::Exit = event {
                if let Some(app) = handle.try_state::<Arc<App>>() {
                    tauri::async_runtime::block_on(app.shutdown());
                }
            }
        });
}
