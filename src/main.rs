// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(unused_macros, unused_imports, clippy::all)]

slint::include_modules!();
use std::error::Error;
use std::time::{Duration, SystemTime};
use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Shell::IsUserAnAdmin;
use windows::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, MB_ICONERROR, MB_ICONINFORMATION, MB_OK,
};
use winreg::enums::*;
use winreg::RegKey;

fn main() -> Result<(), Box<dyn Error>> {
    // 启动时自动检测管理员权限
    if unsafe { !IsUserAnAdmin().as_bool() } {
        if let Err(e) = run_as_admin() {
            eprintln!("UAC 提权失败: {}", e);
        }
        std::process::exit(0);
    }

    let ui = AppWindow::new()?;
    // 初始化Xbox录屏状态
    let xbox_status = match get_xbox_recording_status() {
        Ok(true) => "开启",
        Ok(false) => "禁用",
        Err(_) => "未知",
    };
    ui.set_xbox_status(xbox_status.into());

    let ui_xbox = ui.as_weak();
    ui.on_enable_xbox_recording(move || {
        let ui = ui_xbox.clone().unwrap();
        match enable_xbox_recording() {
            Ok(_) => {
                ui.set_xbox_status("开启".into());
                ui.set_success_message("已开启Xbox屏幕录制".into());
            }
            Err(e) => {
                ui.set_error_message(format!("开启失败: {}", e).into());
            }
        }
    });
    let ui_xbox2 = ui.as_weak();
    ui.on_disable_xbox_recording(move || {
        let ui = ui_xbox2.clone().unwrap();
        match disable_xbox_recording() {
            Ok(_) => {
                ui.set_xbox_status("禁用".into());
                ui.set_success_message("已禁用Xbox屏幕录制".into());
            }
            Err(e) => {
                ui.set_error_message(format!("禁用失败: {}", e).into());
            }
        }
    });
    // 检查Windows更新状态并初始化前端
    let status = get_windows_update_status();
    match status {
        Ok(true) => {
            ui.set_wu_status("开启".into());
            ui.set_wu_action_text("关闭".into());
        }
        Ok(false) => {
            ui.set_wu_status("关闭".into());
            ui.set_wu_action_text("开启".into());
        }
        Err(e) => {
            ui.set_wu_status("未知".into());
            ui.set_wu_action_text("检测失败".into());
            unsafe {
                let msg = format!("检测Windows更新状态失败: {}", e);
                MessageBoxW(
                    Some(HWND(std::ptr::null_mut())),
                    PCWSTR(
                        msg.encode_utf16()
                            .chain(Some(0))
                            .collect::<Vec<u16>>()
                            .as_ptr(),
                    ),
                    PCWSTR("错误\0".encode_utf16().collect::<Vec<u16>>().as_ptr()),
                    MB_OK | MB_ICONERROR,
                );
            }
        }
    }
    let ui_wu = ui.as_weak();
    ui.on_toggle_windows_update(move || {
        let ui = ui_wu.clone().unwrap();
        let current = ui.get_wu_status().to_string();
        let result = if current == "开启" {
            set_windows_update_enabled(false)
        } else {
            set_windows_update_enabled(true)
        };
        match result {
            Ok(_) => {
                // 重新检测状态
                match get_windows_update_status() {
                    Ok(true) => {
                        ui.set_wu_status("开启".into());
                        ui.set_wu_action_text("关闭".into());
                        unsafe {
                            MessageBoxW(
                                None,
                                PCWSTR(
                                    "已开启Windows更新\0"
                                        .encode_utf16()
                                        .collect::<Vec<u16>>()
                                        .as_ptr(),
                                ),
                                PCWSTR("提示\0".encode_utf16().collect::<Vec<u16>>().as_ptr()),
                                MB_OK | MB_ICONINFORMATION,
                            );
                        }
                    }
                    Ok(false) => {
                        ui.set_wu_status("关闭".into());
                        ui.set_wu_action_text("开启".into());
                        unsafe {
                            MessageBoxW(
                                None,
                                PCWSTR(
                                    "已关闭Windows更新\0"
                                        .encode_utf16()
                                        .collect::<Vec<u16>>()
                                        .as_ptr(),
                                ),
                                PCWSTR("提示\0".encode_utf16().collect::<Vec<u16>>().as_ptr()),
                                MB_OK | MB_ICONINFORMATION,
                            );
                        }
                    }
                    Err(e) => {
                        ui.set_wu_status("未知".into());
                        ui.set_wu_action_text("检测失败".into());
                        unsafe {
                            let msg = format!("检测Windows更新状态失败: {}", e);
                            MessageBoxW(
                                None,
                                PCWSTR(
                                    msg.encode_utf16()
                                        .chain(Some(0))
                                        .collect::<Vec<u16>>()
                                        .as_ptr(),
                                ),
                                PCWSTR("错误\0".encode_utf16().collect::<Vec<u16>>().as_ptr()),
                                MB_OK | MB_ICONERROR,
                            );
                        }
                    }
                }
            }
            Err(e) => unsafe {
                let msg = format!("操作Windows更新失败: {}", e);
                MessageBoxW(
                    None,
                    PCWSTR(
                        msg.encode_utf16()
                            .chain(Some(0))
                            .collect::<Vec<u16>>()
                            .as_ptr(),
                    ),
                    PCWSTR("错误\0".encode_utf16().collect::<Vec<u16>>().as_ptr()),
                    MB_OK | MB_ICONERROR,
                );
            },
        }
    });
    let ui_add = ui.as_weak();
    ui.on_add_xiaohe_doublepinyin(move || {
        let ui = ui_add.clone().unwrap();
        match add_xiaohe_doublepinyin_to_registry() {
            Ok(_) => unsafe {
                MessageBoxW(
                    None,
                    PCWSTR(
                        "添加小鹤双拼成功！\0"
                            .encode_utf16()
                            .collect::<Vec<u16>>()
                            .as_ptr(),
                    ),
                    PCWSTR("提示\0".encode_utf16().collect::<Vec<u16>>().as_ptr()),
                    MB_OK | MB_ICONINFORMATION,
                );
            },
            Err(e) => unsafe {
                let msg = format!("添加小鹤双拼失败: {}", e);
                MessageBoxW(
                    None,
                    PCWSTR(
                        msg.encode_utf16()
                            .chain(Some(0))
                            .collect::<Vec<u16>>()
                            .as_ptr(),
                    ),
                    PCWSTR("错误\0".encode_utf16().collect::<Vec<u16>>().as_ptr()),
                    MB_OK | MB_ICONERROR,
                );
            },
        }
    });
    let ui_remove = ui.as_weak();
    ui.on_remove_xiaohe_doublepinyin(move || {
        let ui = ui_remove.clone().unwrap();
        match remove_xiaohe_doublepinyin_from_registry() {
            Ok(_) => unsafe {
                MessageBoxW(
                    None,
                    PCWSTR(
                        "删除小鹤双拼成功！\0"
                            .encode_utf16()
                            .collect::<Vec<u16>>()
                            .as_ptr(),
                    ),
                    PCWSTR("提示\0".encode_utf16().collect::<Vec<u16>>().as_ptr()),
                    MB_OK | MB_ICONINFORMATION,
                );
            },
            Err(e) => unsafe {
                let msg = format!("删除小鹤双拼失败: {}", e);
                MessageBoxW(
                    None,
                    PCWSTR(
                        msg.encode_utf16()
                            .chain(Some(0))
                            .collect::<Vec<u16>>()
                            .as_ptr(),
                    ),
                    PCWSTR("错误\0".encode_utf16().collect::<Vec<u16>>().as_ptr()),
                    MB_OK | MB_ICONERROR,
                );
            },
        }
    });
    let ui_pause = ui.as_weak();
    ui.on_pause_windows_update(move || {
        let ui = ui_pause.clone().unwrap();
        match mod_window_update_pause_time() {
            Ok(_) => unsafe {
                MessageBoxW(
                    None,
                    PCWSTR(
                        "已将Windows更新暂停30天\0"
                            .encode_utf16()
                            .collect::<Vec<u16>>()
                            .as_ptr(),
                    ),
                    PCWSTR("提示\0".encode_utf16().collect::<Vec<u16>>().as_ptr()),
                    MB_OK | MB_ICONINFORMATION,
                );
            },
            Err(e) => unsafe {
                let msg = format!("暂停更新失败: {}", e);
                MessageBoxW(
                    None,
                    PCWSTR(
                        msg.encode_utf16()
                            .chain(Some(0))
                            .collect::<Vec<u16>>()
                            .as_ptr(),
                    ),
                    PCWSTR("错误\0".encode_utf16().collect::<Vec<u16>>().as_ptr()),
                    MB_OK | MB_ICONERROR,
                );
            },
        }
    });
    ui.run()?;
    Ok(())
}

/// 检查Windows更新服务是否开启
fn get_windows_update_status() -> Result<bool, Box<dyn std::error::Error>> {
    // 检查注册表组策略是否存在，不存在或者存在且值为0表示启用自动更新
    let hkcu = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = r"Software\Policies\Microsoft\Windows\WindowsUpdate\AU";
    match hkcu.open_subkey_with_flags(path, KEY_READ) {
        Ok(key) => {
            let value: u32 = key.get_value("NoAutoUpdate").unwrap_or(0);
            if value == 0 {
                Ok(true)
            } else {
                Ok(false)
            }
        }
        Err(_) => Ok(true),
    }
}

/// 启用或禁用Windows更新服务
fn set_windows_update_enabled(enable: bool) -> Result<(), Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = r"Software\Policies\Microsoft\Windows\WindowsUpdate\AU";
    let key = match hkcu.open_subkey_with_flags(path, KEY_SET_VALUE) {
        Ok(k) => k,
        Err(_) => hkcu.create_subkey(path)?.0,
    };
    let mut value = 0u32;
    if !enable {
        value = 1;
    }
    key.set_value("NoAutoUpdate", &value)?; // 0表示启用自动更新
    Ok(())
}

#[cfg(windows)]
fn run_as_admin() -> Result<(), Box<dyn std::error::Error>> {
    use std::env;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;
    let exe = env::current_exe()?;
    let exe_wide: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let params: Vec<u16> = OsStr::new("").encode_wide().chain(Some(0)).collect();
    let verb: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();
    let res: windows::Win32::Foundation::HINSTANCE = unsafe {
        if cfg!(debug_assertions) {
            use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;
            ShellExecuteW(
                Some(HWND(std::ptr::null_mut())),
                PCWSTR(verb.as_ptr()),
                PCWSTR(exe_wide.as_ptr()),
                PCWSTR(params.as_ptr()),
                PCWSTR(std::ptr::null()),
                SW_SHOW,
            )
        } else {
            use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;

            ShellExecuteW(
                Some(HWND(std::ptr::null_mut())),
                PCWSTR(verb.as_ptr()),
                PCWSTR(exe_wide.as_ptr()),
                PCWSTR(params.as_ptr()),
                PCWSTR(std::ptr::null()),
                SW_HIDE,
            )
        }
    };
    if res.0 as usize > 32 {
        Ok(())
    } else {
        Err("UAC 提权失败".into())
    }
}
fn remove_xiaohe_doublepinyin_from_registry() -> Result<(), Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = r"Software\Microsoft\InputMethod\Settings\CHS";
    let key = hkcu.open_subkey_with_flags(path, KEY_SET_VALUE)?;
    let value_name = "UserDefinedDoublePinyinScheme0";
    match key.delete_value(value_name) {
        Ok(_) => Ok(()),
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // 不存在也算成功
        Err(e) => Err(Box::new(e)),
    }
}

fn add_xiaohe_doublepinyin_to_registry() -> Result<(), Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = r"Software\Microsoft\InputMethod\Settings\CHS";
    let (key, _) = hkcu.create_subkey(path)?;
    let value_name = "UserDefinedDoublePinyinScheme0";
    let value_data = "小鹤双拼*2*^*iuvdjhcwfg^xmlnpbksqszxkrltvyovt";
    key.set_value(value_name, &value_data)?;
    Ok(())
}

fn mod_window_update_pause_time() -> std::io::Result<()> {
    // 打开注册表键
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key = hklm.open_subkey_with_flags(
        "SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings",
        KEY_WRITE,
    )?;

    // 设置暂停时间，比如暂停 365 天
    let now = SystemTime::now();
    let end_time = now + Duration::from_secs(365 * 100 * 24 * 60 * 60); // 365 天

    // 转成 ISO 8601 格式字符串
    let end_time_str = systemtime_to_iso8601(end_time);

    // 写入 REG_SZ
    key.set_value("PauseUpdatesExpiryTime", &end_time_str)?;

    Ok(())
}

// SystemTime 转 ISO 8601 UTC 字符串
fn systemtime_to_iso8601(st: SystemTime) -> String {
    use chrono::{DateTime, Utc};
    let datetime: DateTime<Utc> = st.into();
    datetime.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

// 禁用xbox录屏通过注册表
fn disable_xbox_recording() -> Result<(), Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = r"System\GameConfigStore";
    let key = hkcu.open_subkey_with_flags(path, KEY_SET_VALUE)?;
    key.set_value("GameDVR_Enabled", &0u32)?; // 0表示禁用
    let path2 = r"Software\Microsoft\Windows\CurrentVersion\GameDVR";
    let key2 = hkcu.open_subkey_with_flags(path2, KEY_SET_VALUE)?;
    key2.set_value("AppCaptureEnabled", &0u32)?; // 0表示禁用
    Ok(())
}
// 启用xbox录屏通过注册表
fn enable_xbox_recording() -> Result<(), Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = r"System\GameConfigStore";
    let key = hkcu.open_subkey_with_flags(path, KEY_SET_VALUE)?;
    key.set_value("GameDVR_Enabled", &1u32)?; // 1表示启用
    let path2 = r"Software\Microsoft\Windows\CurrentVersion\GameDVR";
    let key2 = hkcu.open_subkey_with_flags(path2, KEY_SET_VALUE)?;
    key2.set_value("AppCaptureEnabled", &1u32)?; // 1表示启用
    Ok(())
}

// 获取Xbox录屏状态
fn get_xbox_recording_status() -> Result<bool, Box<dyn std::error::Error>> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = r"System\GameConfigStore";
    let key = hkcu.open_subkey(path)?;
    let enabled: u32 = key.get_value("GameDVR_Enabled")?;
    Ok(enabled != 0)
}
