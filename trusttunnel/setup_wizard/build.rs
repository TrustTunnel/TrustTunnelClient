fn main() {
    #[cfg(windows)]
    {
        let _ = windres::Build::new().compile("resources/setup_wizard.rc");
    }
}
