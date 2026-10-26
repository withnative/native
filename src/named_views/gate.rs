//! Production activation is a deployment decision, never a request parameter.
use super::*;
use std::future::Future;
#[cfg(test)]
tokio::task_local! {static TEST_ENABLED:bool;}
tokio::task_local! {static DEADLINE:Instant;}
pub(crate) fn enabled() -> bool {
    #[cfg(test)]
    {
        TEST_ENABLED.try_with(|b| *b).unwrap_or(false)
    }
    #[cfg(not(test))]
    {
        static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *ENABLED.get_or_init(|| std::env::var("NATIVE_NAMED_VIEWS").as_deref() == Ok("1"))
    }
}
pub(crate) fn require() -> Result<()> {
    if enabled() {
        Ok(())
    } else {
        Err(invalid(
            "named view admission is disabled; enabling requires Richard's decision",
        ))
    }
}
pub(crate) fn deadline() -> Instant {
    DEADLINE
        .try_with(|d| *d)
        .unwrap_or_else(|_| Instant::now() + Duration::from_secs(2))
}
pub(crate) async fn scope<T>(deadline: Instant, work: impl Future<Output = T>) -> T {
    DEADLINE.scope(deadline, work).await
}
#[cfg(test)]
pub(crate) async fn testing<T>(enabled: bool, work: impl Future<Output = T>) -> T {
    TEST_ENABLED.scope(enabled, work).await
}
