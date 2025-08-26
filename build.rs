fn main() {
    slint_build::compile("ui/app-window.slint").expect("Slint build failed");
    // 设置 Windows 应用图标
    #[cfg(windows)]
    {
        embed_resource::compile("ui/icon/icon.rc", embed_resource::NONE);
    }
}
