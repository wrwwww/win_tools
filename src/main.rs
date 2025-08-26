// Prevent console window in addition to Slint window in Windows release builds when, e.g., starting the app via file manager. Ignored on other platforms.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::error::Error;

slint::include_modules!();

fn main() -> Result<(), Box<dyn Error>> {
    let ui = AppWindow::new()?;
    let ui_add = ui.as_weak();
    ui.on_add_xiaohe_doublepinyin(move || {
        let ui = ui_add.clone().unwrap();
        match add_xiaohe_doublepinyin_to_registry() {
            Ok(_) => ui.set_success_message("添加小鹤双拼成功！".into()),
            Err(e) => ui.set_error_message(format!("添加小鹤双拼失败: {}", e).into()),
        }
    });
    let ui_remove = ui.as_weak();
    ui.on_remove_xiaohe_doublepinyin(move || {
        let ui = ui_remove.clone().unwrap();
        match remove_xiaohe_doublepinyin_from_registry() {
            Ok(_) => ui.set_success_message("删除小鹤双拼成功！".into()),
            Err(e) => ui.set_error_message(format!("删除小鹤双拼失败: {}", e).into()),
        }
    });
    ui.run()?;
    Ok(())
}
fn remove_xiaohe_doublepinyin_from_registry() -> Result<(), Box<dyn std::error::Error>> {
    use winreg::enums::*;
    use winreg::RegKey;
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
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = r"Software\Microsoft\InputMethod\Settings\CHS";
    let (key, _) = hkcu.create_subkey(path)?;
    let value_name = "UserDefinedDoublePinyinScheme0";
    let value_data = "小鹤双拼*2*^*iuvdjhcwfg^xmlnpbksqszxkrltvyovt";
    key.set_value(value_name, &value_data)?;
    Ok(())
}
