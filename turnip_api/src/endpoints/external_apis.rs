use std::{
    ops::Deref,
    sync::atomic::{AtomicU64, Ordering},
};

struct ExternalApiParams {
    key: String,
    // max_calls_per_s: Option<u64>,
    call_quota_per_duration: u64,
    call_quota_duration_s: u64,
}

/// Simple wrapper struct that ensures the contents start on their own cache line.
///
/// TODO forces 128-byte alignment because some chips have 128-byte cache line, some have 64-byte.
///
/// TODO if this is held inside a larger struct, there is no guarantee other fields in that struct will not also occupy this cache line.
/// Is there some way to force Rust to pad out the size of the struct to 128?
#[repr(align(128))]
struct CacheLine<T>(T);
impl<T> CacheLine<T> {
    pub fn new(v: T) -> Self {
        assert!(std::mem::size_of::<T>() <= 128);
        Self(v)
    }
}
impl<T> Deref for CacheLine<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

struct ExternalApiRateLimiter {
    // Read-only
    params: ExternalApiParams,
    quota_period_start: std::time::Instant,

    // Only ever touched when your ticket is up, so no contention
    quota_period_remaining_tickets: AtomicU64,
    quota_period_end_s_since_start: AtomicU64,
    // // Use micros so that we can support max_calls_per_s up to 1E6
    // next_ticket_utc_micros: AtomicU64,

    // This is only ever atomically incremented, so will have low contention
    tickets_issued: AtomicU64,
    // This is constantly read & infrequently written, so put it on a separate cache line
    next_ticket: CacheLine<AtomicU64>,
}

enum ExternalApiRateLimitError {
    ExceededQuota,
}

impl ExternalApiRateLimiter {
    pub fn from_params(params: ExternalApiParams) -> Self {
        Self {
            quota_period_start: std::time::Instant::now(),
            quota_period_end_s_since_start: AtomicU64::new(params.call_quota_duration_s),
            quota_period_remaining_tickets: AtomicU64::new(params.call_quota_per_duration),
            tickets_issued: AtomicU64::new(0),
            next_ticket: CacheLine::new(AtomicU64::new(0)),
            params,
        }
    }

    pub fn perform_rate_limited_action<T, F>(&self, f: F) -> Result<T, ExternalApiRateLimitError>
    where
        F: FnOnce(&str) -> T,
    {
        // Take a ticket
        let ticket = self.tickets_issued.fetch_add(1, Ordering::Release);
        // let timestamp = todo!();
        // Wait for that ticket to be the active ticket
        loop {
            let next_ticket = self.next_ticket.load(Ordering::Acquire);
            if next_ticket == ticket {
                break;
            }
            // let expected_duration = self.next_ticket_utc_micros (next_ticket - ticket - 1) *
            // TODO sleep until it's likely that the next ticket is ready
        }
        // It's our ticket's turn, check if the quote allows us to go.
        // We are the only core executing this code right now.
        // Make sure we know which quota window we exist in...
        match std::time::Instant::now().checked_duration_since(self.quota_period_start) {
            Some(since_start) => {
                let s_since_start = since_start.as_secs();
                if s_since_start > self.quota_period_end_s_since_start.load(Ordering::Acquire) {
                    self.quota_period_end_s_since_start.store(
                        (s_since_start / self.params.call_quota_duration_s)
                            * self.params.call_quota_duration_s,
                        Ordering::Release,
                    );
                    self.quota_period_remaining_tickets
                        .store(self.params.call_quota_per_duration, Ordering::Release);
                }
            }
            None => {
                println!("s_since_start underflow");
            }
        };
        // ...then try to take a ticket out of it
        let val = match self.quota_period_remaining_tickets.fetch_update(
            Ordering::Release,
            Ordering::Acquire,
            |remaining| {
                if remaining > 0 {
                    Some(remaining - 1)
                } else {
                    None
                }
            },
        ) {
            Ok(_) => {
                let val = f(&self.params.key);
                Ok(val)
            }
            Err(_zero) => Err(ExternalApiRateLimitError::ExceededQuota),
        };
        // Regardless of whether we went, let the next ticket go
        self.next_ticket.fetch_add(1, Ordering::Release);
        val
    }
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use super::{ExternalApiParams, ExternalApiRateLimiter};

    #[test]
    fn test_rate_limiter_prevents_exceeding_quota_inside_single_period() {
        const N_CALLS_PER_QUOTA: u64 = 1000;

        let rate_limiter = ExternalApiRateLimiter::from_params(ExternalApiParams {
            key: "".to_string(),
            call_quota_per_duration: N_CALLS_PER_QUOTA,
            call_quota_duration_s: 10,
        });

        const N_THREADS: u64 = 64;
        const N_CALLS_PER_THREAD: u64 = N_CALLS_PER_QUOTA / N_THREADS + 5;
        const N_TOTAL_CALLS: u64 = N_CALLS_PER_THREAD * N_THREADS;
        assert!(N_TOTAL_CALLS > N_CALLS_PER_QUOTA);

        let go_flag = AtomicBool::new(false);
        let n_successes = AtomicU64::new(0);
        let n_fails = AtomicU64::new(0);

        std::thread::scope(|scope| {
            let mut thread_handles = vec![];
            for _ in 0..N_THREADS {
                thread_handles.push(scope.spawn(|| {
                    while !go_flag.load(Ordering::Acquire) {}

                    for _ in 0..N_CALLS_PER_THREAD {
                        match rate_limiter.perform_rate_limited_action(|_| {
                            n_successes.fetch_add(1, Ordering::AcqRel)
                        }) {
                            Ok(_) => {}
                            Err(_) => {
                                n_fails.fetch_add(1, Ordering::AcqRel);
                            }
                        };
                    }
                }));
            }

            // start the threads off
            go_flag.store(true, Ordering::Release);

            for handle in thread_handles {
                handle.join().expect("Failed to join thread");
            }
        });

        assert_eq!(n_successes.load(Ordering::Acquire), N_CALLS_PER_QUOTA);
        assert_eq!(
            n_fails.load(Ordering::Acquire),
            N_TOTAL_CALLS - N_CALLS_PER_QUOTA
        );
    }
}
