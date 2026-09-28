//! Core library for the `sandy` workspace.
//!
//! This is a starting point. Replace [`greet`] and [`Error`] with real
//! functionality as the crate grows; they exist so the workspace builds, tests,
//! and lints cleanly from the first commit.

/// Errors returned by [`greet`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The provided name was empty.
    #[error("name must not be empty")]
    EmptyName,
}

/// Build a greeting for `name`.
///
/// # Errors
///
/// Returns [`Error::EmptyName`] when `name` is empty.
///
/// # Examples
///
/// ```
/// assert_eq!(sandy_core::greet("world")?, "Hello, world!");
/// # Ok::<(), sandy_core::Error>(())
/// ```
pub fn greet(name: &str) -> Result<String, Error> {
    if name.is_empty() {
        return Err(Error::EmptyName);
    }
    Ok(format!("Hello, {name}!"))
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case("sandy", "Hello, sandy!")]
    #[case("world", "Hello, world!")]
    fn greets_a_name(#[case] input: &str, #[case] expected: &str) -> anyhow::Result<()> {
        assert_eq!(greet(input)?, expected);
        Ok(())
    }

    #[test]
    fn rejects_an_empty_name() {
        assert!(matches!(greet(""), Err(Error::EmptyName)));
    }
}
