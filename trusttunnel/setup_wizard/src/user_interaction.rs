use crate::Mode;
use dialoguer::theme::ColorfulTheme;
use dialoguer::{Confirm, Input, Password, Select};
use once_cell::sync::Lazy;
use std::fs;
use std::io::Write;
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;

pub static THEME: Lazy<ColorfulTheme> = Lazy::new(ColorfulTheme::default);

/// Restore the terminal state after an interrupt.
fn restore_terminal() {
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = crossterm::execute!(
        std::io::stdout(),
        crossterm::cursor::Show,
        crossterm::event::DisableBracketedPaste
    );
    let _ = std::io::stdout().flush();
}

/// Install a handler that restores the terminal before exiting on Ctrl+C.
pub fn install_interrupt_handler() {
    if let Err(error) = ctrlc::set_handler(|| {
        restore_terminal();
        std::process::exit(130);
    }) {
        eprintln!("Warning: cannot install the Ctrl+C handler: {error}");
    }
}

fn handle_interaction<T>(result: std::io::Result<T>) -> T {
    match result {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
            restore_terminal();
            std::process::exit(130);
        }
        Err(error) => panic!("Interaction failure: {error}"),
    }
}

/// Ask user to enter a raw line using bracketed paste mode.
/// This delivers the entire paste as a single event, bypassing the TTY canonical
/// mode line buffer that truncates long inputs like deep-link URIs.
/// This function supports only Paste and Enter events.
pub fn ask_for_input_raw_line(message: &str) -> String {
    use crossterm::event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyModifiers,
    };
    use crossterm::execute;
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

    print!("? {} › ", message);
    std::io::stdout().flush().unwrap();

    enable_raw_mode().unwrap();
    execute!(std::io::stdout(), EnableBracketedPaste).unwrap();

    let mut result = String::new();
    loop {
        match event::read().unwrap() {
            Event::Paste(text) => {
                result = text;

                // As long as deeplink URI contains only ASCII characters,
                // we can safety slice by bytes.
                let bytes = result.as_bytes();
                let print_len = bytes.len().min(1024);
                let mut stdout = std::io::stdout();

                stdout.write_all(&bytes[..print_len]).unwrap();
                if bytes.len() > 1024 {
                    stdout.write_all(b"...").unwrap();
                }
                stdout.flush().unwrap();
                break;
            }
            Event::Key(key)
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && key.code == KeyCode::Char('c') =>
            {
                execute!(std::io::stdout(), DisableBracketedPaste).unwrap();
                disable_raw_mode().unwrap();
                println!();
                std::process::exit(130);
            }
            Event::Key(key) if key.code == KeyCode::Enter => {
                break;
            }
            _ => {}
        }
    }

    execute!(std::io::stdout(), DisableBracketedPaste).unwrap();
    disable_raw_mode().unwrap();
    println!();

    result
}

/// Ask user to enter a value.
/// If [`default`] is [`Some`], suggest the value in the prompt.
pub fn ask_for_input<T>(message: &str, default: Option<T>) -> T
where
    T: Clone + Default + FromStr + ToString,
    <T as FromStr>::Err: ToString,
{
    if crate::get_mode() == Mode::NonInteractive {
        return default.expect("Expecting a user input in non-interactive mode");
    }

    if default.is_some() {
        handle_interaction(
            Input::<T>::with_theme(THEME.deref())
                .with_prompt(message)
                .show_default(default.is_some())
                .default(default.unwrap_or_default())
                .interact(),
        )
    } else {
        handle_interaction(
            Input::<T>::with_theme(THEME.deref())
                .with_prompt(message)
                .interact(),
        )
    }
}

/// Ask if one wants to do something (yes/no).
/// No by default.
pub fn ask_for_agreement(message: &str) -> bool {
    assert_ne!(
        crate::get_mode(),
        Mode::NonInteractive,
        "Expecting a user input in non-interactive mode"
    );
    ask_for_agreement_with_default(message, false)
}

/// Ask if one wants to do something (yes/no).
/// `default` by default.
pub fn ask_for_agreement_with_default(message: &str, default: bool) -> bool {
    if crate::get_mode() == Mode::NonInteractive {
        return default;
    }

    handle_interaction(
        Confirm::with_theme(THEME.deref())
            .with_prompt(message)
            .default(default)
            .show_default(true)
            .interact(),
    )
}

/// Ask user to enter a password in a secure way
pub fn ask_for_password(message: &str) -> String {
    assert_ne!(
        crate::get_mode(),
        Mode::NonInteractive,
        "Expecting a user input in non-interactive mode"
    );
    handle_interaction(
        Password::with_theme(THEME.deref())
            .with_prompt(message)
            .interact(),
    )
}

/// Check if a file exists and if it does, ask if one wants to overwrite it
pub fn checked_overwrite(path: &str, message: &str) -> bool {
    crate::get_mode() == Mode::NonInteractive
        || !fs::metadata(Path::new(&path))
            .as_ref()
            .map(fs::Metadata::is_file)
            .unwrap_or_default()
        || ask_for_agreement(message)
}

/// Ask user to select a variant. Returns index of the selected variant.
pub fn select_index<S: Into<String>>(
    prompt: S,
    variants: &[&str],
    default: Option<usize>,
) -> usize {
    if crate::get_mode() == Mode::NonInteractive {
        return default.expect("Expecting a user input in non-interactive mode");
    }

    let selected = handle_interaction(
        Select::with_theme(THEME.deref())
            .with_prompt(prompt)
            .items(variants)
            .report(true)
            .default(default.unwrap_or_default())
            .interact_opt(),
    );
    match selected {
        Some(index) => index,
        None => {
            restore_terminal();
            std::process::exit(130);
        }
    }
}

/// Ask user to select a variant. Returns the selected variant.
pub fn select_variant<'a, S>(prompt: S, variants: &[&'a str], default: Option<usize>) -> &'a str
where
    S: Into<String>,
{
    variants[select_index(prompt, variants, default)]
}
