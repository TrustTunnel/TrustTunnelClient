use std::fs;
use std::ops::Deref;
use std::path::Path;
use std::str::FromStr;
use dialoguer::{Confirm, Input, Password, Select};
use dialoguer::theme::ColorfulTheme;
use once_cell::sync::Lazy;
use crate::Mode;

pub static THEME: Lazy<ColorfulTheme> = Lazy::new(ColorfulTheme::default);

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
        Input::<T>::with_theme(THEME.deref())
            .with_prompt(message)
            .show_default(default.is_some())
            .default(default.unwrap_or_default())
            .interact().unwrap()
    } else {
        Input::<T>::with_theme(THEME.deref())
            .with_prompt(message)
            .interact().unwrap()
    }
}

/// Ask if one wants to do something (yes/no).
/// No by default.
pub fn ask_for_agreement(message: &str) -> bool {
    assert_ne!(crate::get_mode(), Mode::NonInteractive, "Expecting a user input in non-interactive mode");
    ask_for_agreement_with_default(message, false)
}

/// Ask if one wants to do something (yes/no).
/// `default` by default.
pub fn ask_for_agreement_with_default(message: &str, default: bool) -> bool {
    if crate::get_mode() == Mode::NonInteractive {
        return default;
    }

    Confirm::with_theme(THEME.deref())
        .with_prompt(message)
        .default(default)
        .show_default(true)
        .interact()
        .unwrap()
}

/// Ask user to enter a password in a secure way
pub fn ask_for_password(message: &str) -> String {
    assert_ne!(crate::get_mode(), Mode::NonInteractive, "Expecting a user input in non-interactive mode");
    Password::with_theme(THEME.deref())
        .with_prompt(message)
        .interact()
        .unwrap()
}

/// Check if a file exists and if it does, ask if one wants to overwrite it
pub fn checked_overwrite(path: &str, message: &str) -> bool {
    crate::get_mode() == Mode::NonInteractive
        || !fs::metadata(Path::new(&path)).as_ref()
        .map(fs::Metadata::is_file)
        .unwrap_or_default()
        || ask_for_agreement(message)
}

/// Ask user to select a variant. Returns index of the selected variant.
pub fn select_index<S: Into<String>>(prompt: S, variants: &[&str], default: Option<usize>) -> usize {
    if crate::get_mode() == Mode::NonInteractive {
        return default.expect("Expecting a user input in non-interactive mode");
    }

    Select::with_theme(THEME.deref())
        .with_prompt(prompt)
        .items(variants)
        .report(true)
        .default(default.unwrap_or_default())
        .interact_opt().expect("Interaction failure")
        .expect("None selected")
}

/// Ask user to select a variant. Returns the selected variant.
pub fn select_variant<'a, S>(prompt: S, variants: &[&'a str], default: Option<usize>) -> &'a str
    where S: Into<String>
{
    variants[select_index(prompt, variants, default)]
}
