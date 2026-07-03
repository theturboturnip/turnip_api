pub type AnyError = Box<dyn std::error::Error + Send + Sync>;

/// A sentinel type that, when used as the Result-error for a function,
/// drops all errors[^1] silently.
/// Useful for arbitrarily bailing when individual errors are not relevant,
/// e.g. for time-zone conversion errors based on user input.
///
/// [^1] - At least, those which implement Debug.
pub struct IgnoreError {}
impl<T: core::fmt::Debug> From<T> for IgnoreError {
    fn from(_value: T) -> Self {
        Self {}
    }
}

/// A sentinel type that, when used as the Result-error for a function,
/// log::debug!s all errors[^1] before dropping them silently.
/// Useful for arbitrarily bailing when individual errors are not relevant.
///
/// [^1] - At least, those which implement Debug.
pub struct DebugError {}
impl<T: core::fmt::Debug> From<T> for DebugError {
    fn from(value: T) -> Self {
        log::debug!("{:?}", value);
        Self {}
    }
}
