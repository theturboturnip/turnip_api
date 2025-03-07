use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        RwLock,
    },
};

use jsonwebtoken::{DecodingKey, EncodingKey, TokenData};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::{
    de::{Expected, Visitor},
    Deserialize, Serialize,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(usize)]
pub enum ApiTarget {
    RundownV1,
    Dummy,
}
const API_TARGET_TO_STR: [&'static str; 2] = ["turnip_rundown/v1", "dummy"];
impl From<ApiTarget> for &'static str {
    fn from(value: ApiTarget) -> Self {
        API_TARGET_TO_STR[value as usize]
    }
}
impl ApiTarget {
    fn try_from_str(s: &str) -> Option<Self> {
        match s {
            val if (val == API_TARGET_TO_STR[ApiTarget::RundownV1 as usize]) => {
                Some(ApiTarget::RundownV1)
            }
            val if (val == API_TARGET_TO_STR[ApiTarget::Dummy as usize]) => Some(ApiTarget::Dummy),
            _ => None,
        }
    }
}

impl Serialize for ApiTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str((*self).into())
    }
}
impl<'de> Deserialize<'de> for ApiTarget {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ExpectedApiTarget;
        impl Expected for ExpectedApiTarget {
            fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "one of")?;
                for str in API_TARGET_TO_STR {
                    write!(formatter, " '{str}'")?;
                }
                Ok(())
            }
        }
        struct Visit;
        impl<'de> Visitor<'de> for Visit {
            type Value = ApiTarget;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                ExpectedApiTarget.fmt(formatter)
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ApiTarget::try_from_str(v).ok_or(serde::de::Error::invalid_value(
                    serde::de::Unexpected::Str(v),
                    &ExpectedApiTarget,
                ))
            }
        }

        deserializer.deserialize_str(Visit)
    }
}

/// Mapping of app-ids to the runtime information about that app.
/// This is always indexed by valid app strings - or at least not user-controlled strings.
/// We pass in the appid from known-valid JWTs, and we are the only people who can create them.
/// That means we can use a fast hash map without worrying about HashDos attacks.
struct AppRuntimeInfos(FxHashMap<String, RwLock<ApiAppRuntimeInfo>>);
impl AppRuntimeInfos {
    fn new(apps: HashMap<String, ApiAppParams>) -> Self {
        let mut map = FxHashMap::default();
        map.extend(apps.into_iter().map(|(app_id, params)| {
            (
                app_id.clone(),
                RwLock::new(ApiAppRuntimeInfo::new(app_id, params)),
            )
        }));
        Self(map)
    }
    fn get_app_runtime(&self, key: &str) -> Option<&RwLock<ApiAppRuntimeInfo>> {
        self.0.get(key)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub struct ApiAppParams {
    /// The API target this app can use
    api: ApiTarget,
    /// The maximum amount of claims we will generate for this app at this time
    max_outstanding_claims: usize,
    /// The maximum amount of uses we allow per claim, to avoid one claim starving out all the others
    max_requests_per_claim: u64,
    /// The duration of time (in seconds) that new claims are given before they time out
    claim_timeout_s: u64,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnipApiParams {
    /// The key used to generate and validate API claims with the HMAC-SHA-256 scheme
    key_base64: String,
    apps: HashMap<String, ApiAppParams>,
}

type SecureRng = rand_chacha::ChaCha20Rng;

struct ApiAppRuntimeInfo {
    app_id: String,
    params: ApiAppParams,
    /// Mapping of (Claim GUID -> number of requests, timeout)
    /// Only used on verified claims, which we generate, so can be a fast hash map
    outstanding_claims: FxHashMap<String, OutstandingClaimInfo>,
    /// Secure RNG used for generating the random Subject for each token
    rand: SecureRng,
}

impl ApiAppRuntimeInfo {
    fn new(app_id: String, params: ApiAppParams) -> Self {
        Self {
            app_id,
            params,
            outstanding_claims: FxHashMap::with_capacity_and_hasher(
                params.max_outstanding_claims,
                FxBuildHasher::default(),
            ),
            rand: SecureRng::from_os_rng(),
        }
    }
    fn validate_request(
        &self,
        token_str: &str,
        target: ApiTarget,
    ) -> Result<(), ValidateTokenError> {
        if self.params.api != target {
            return Err(ValidateTokenError::ClaimTargetsIncorrectApi {
                api_claimed: self.params.api,
                api_requested: target,
            });
        }

        if let Some(claim) = self.outstanding_claims.get(token_str) {
            // TODO check those atomics
            match claim
                .requests
                .fetch_update(Ordering::Release, Ordering::Acquire, |x| {
                    if x >= self.params.max_requests_per_claim {
                        None
                    } else {
                        Some(x + 1)
                    }
                }) {
                Ok(_prev_val) => Ok(()),
                Err(_prev_val) => Err(ValidateTokenError::ClaimExceedsUses),
            }
        } else {
            Err(ValidateTokenError::ClaimHasInvalidAppId)
        }
    }
    fn generate_token(
        &mut self,
        key: &EncodingKey,
        utc_timestamp: u64,
    ) -> Result<String, GenerateTokenError> {
        // If we know about more claims than the app supports at a time,
        // do a sweep to remove outdated ones and check again.
        // TODO: under heavy load doing a whole scan over and over might be too expensive. maintain a "next timeout" timestamp
        // and only scan once that's passed
        if self.outstanding_claims.len() >= self.params.max_outstanding_claims {
            // Remove where timeout < timestamp, i.e. retain where timeout > timestamp
            // Use (timeout+leeway) to ensure that we leave things alive for long enough to handle clock skew
            self.outstanding_claims
                .retain(|_token, outstanding_claim_info| {
                    outstanding_claim_info.timeout + TOKEN_TIMEOUT_LEEWAY > utc_timestamp
                    // Don't do this :)
                    // && outstanding_claim_info.uses.load(Ordering::SeqCst) < self.params.max_uses_per_claim
                });
            if self.outstanding_claims.len() >= self.params.max_outstanding_claims {
                return Err(GenerateTokenError::AppHasTooManyOutstandingClaims);
            }
        }

        // We have enough room, generate a new claim
        let claim = TurnipApiClaim {
            app_id: self.app_id.clone(),
            exp: utc_timestamp + self.params.claim_timeout_s,
            aud: TURNIP_API_AUD.to_string(),
            sub: self.rand.next_u64().to_string(),
        };
        let encoded =
            jsonwebtoken::encode(&jsonwebtoken::Header::new(TOKEN_ALGORITHM), &claim, &key)
                .map_err(|err| GenerateTokenError::JwtError(err))?;
        self.outstanding_claims.insert(
            encoded.clone(),
            OutstandingClaimInfo {
                requests: AtomicU64::new(0),
                timeout: claim.exp,
            },
        );
        Ok(encoded)
    }
}

struct OutstandingClaimInfo {
    requests: AtomicU64,
    timeout: u64,
}

const TURNIP_API_AUD: &'static str = "turnip_api";

#[derive(Debug, Serialize, Deserialize)]
struct TurnipApiClaim {
    /// The ID of the application requesting access.
    /// Must be one of a set of expected applications for that target
    app_id: String,
    /// Expiration time (as UTC timestamp), automatically validated
    exp: u64,
    /// Audience, must be TURNIP_API_AUD
    aud: String,
    /// Subject (the user of the JWT, which is just a random string for our purposes)
    sub: String,
}

#[derive(Debug, Clone)]
pub enum ValidateTokenError {
    JwtError(jsonwebtoken::errors::Error),
    // Either the app doesn't exist or the app doesn't know about this claim
    ClaimHasInvalidAppId,
    ClaimHasExpired,
    ClaimHasBadAudience,
    ClaimTargetsIncorrectApi {
        api_claimed: ApiTarget,
        api_requested: ApiTarget,
    },
    ClaimExceedsUses,
}

#[derive(Debug, Clone)]
pub enum GenerateTokenError {
    JwtError(jsonwebtoken::errors::Error),
    BadAppId,
    AppHasTooManyOutstandingClaims,
}

const TOKEN_ALGORITHM: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::HS256;
const TOKEN_TIMEOUT_LEEWAY: u64 = 30;

pub struct AppAuth {
    dec_key: jsonwebtoken::DecodingKey,
    enc_key: jsonwebtoken::EncodingKey,
    validation: jsonwebtoken::Validation,
    app_runtimes: AppRuntimeInfos,
}
impl AppAuth {
    pub fn from_config(params: TurnipApiParams) -> Self {
        let mut validation = jsonwebtoken::Validation::new(TOKEN_ALGORITHM);
        // We manually validate the EXP so we don't need to worry about dependency-injecting time at test time
        validation.validate_exp = false;
        validation.set_audience(&[TURNIP_API_AUD]);
        validation.set_required_spec_claims(&["app_id", "exp", "aud", "sub"]);

        Self {
            dec_key: DecodingKey::from_base64_secret(&params.key_base64)
                .expect("Failed to decode key base64"),
            enc_key: EncodingKey::from_base64_secret(&params.key_base64)
                .expect("Failed to decode key base64"),
            validation,
            app_runtimes: AppRuntimeInfos::new(params.apps),
        }
    }

    /// Given a JWT token, validate it against the App ID it claims to have
    /// and what ApiTarget endpoint it's been sent to, and increment the number of requests
    /// (assuming you aren't going over the request limit)
    pub fn validate_request(
        &self,
        token_str: &str,
        target: ApiTarget,
        utc_timestamp: u64,
    ) -> Result<(), ValidateTokenError> {
        let key = &self.dec_key;
        let token: TokenData<TurnipApiClaim> =
            jsonwebtoken::decode(token_str, key, &self.validation).map_err(|err| {
                match err.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                        // This should never happen because we tell the validator to not check the timeout leeway
                        ValidateTokenError::ClaimHasExpired
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                        ValidateTokenError::ClaimHasBadAudience
                    }
                    _ => ValidateTokenError::JwtError(err),
                }
            })?;
        if token.claims.exp + TOKEN_TIMEOUT_LEEWAY < utc_timestamp {
            return Err(ValidateTokenError::ClaimHasExpired);
        }
        match self.app_runtimes.get_app_runtime(&token.claims.app_id) {
            Some(app_runtime) => {
                let app_runtime = app_runtime.read().expect("Poisoned lock somehow");
                app_runtime.validate_request(token_str, target)
            }
            None => Err(ValidateTokenError::ClaimHasInvalidAppId),
        }
    }
    /// Given an App ID, generate a new token for it (if it has spare outstanding claims)
    pub fn generate_token(
        &self,
        app_id: &str,
        utc_timestamp: u64,
    ) -> Result<String, GenerateTokenError> {
        let key = &self.enc_key;
        match self.app_runtimes.get_app_runtime(app_id) {
            Some(app_runtime) => {
                let mut app_runtime = app_runtime.write().expect("Poisoned lock somehow");
                app_runtime.generate_token(key, utc_timestamp)
            }
            None => Err(GenerateTokenError::BadAppId),
        }
    }
    // TODO renew tokens?
}

#[cfg(test)]
pub mod test {
    use std::{
        collections::{HashMap, HashSet},
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };

    use jsonwebtoken::TokenData;

    use super::{
        ApiAppParams, ApiTarget, AppAuth, TurnipApiClaim, TurnipApiParams, TOKEN_TIMEOUT_LEEWAY,
    };

    const MAX_OUTSTANDING_CLAIMS: usize = 150;
    const MAX_REQUESTS_PER_CLAIM: u64 = 100;
    const CLAIM_TIMEOUT_S: u64 = 15 * 60;

    fn test_env() -> AppAuth {
        AppAuth::from_config(TurnipApiParams {
            // deadbeefDEADBEEFdeadbeefDEADBEEFdeadbeefDEADBEEFdeadbeefDEADBEEF
            key_base64: "ZGVhZGJlZWZERUFEQkVFRmRlYWRiZWVmREVBREJFRUZkZWFkYmVlZkRFQURCRUVGZGVhZGJlZWZERUFEQkVFRg==".to_string(),
            apps: HashMap::from([
                (
                    "app1".to_string(),
                    ApiAppParams {
                        api: ApiTarget::RundownV1,
                        max_outstanding_claims: MAX_OUTSTANDING_CLAIMS,
                        max_requests_per_claim: MAX_REQUESTS_PER_CLAIM,
                        claim_timeout_s: CLAIM_TIMEOUT_S,
                    }
                )
            ])
        })
    }

    #[test]
    fn test_deserialize_env() {
        let deserialized: TurnipApiParams = serde_json::from_str(r#"
        {
            "key_base64": "ZGVhZGJlZWZERUFEQkVFRmRlYWRiZWVmREVBREJFRUZkZWFkYmVlZkRFQURCRUVGZGVhZGJlZWZERUFEQkVFRg==",
            "apps": {
                "app1": {
                    "api": "turnip_rundown/v1",
                    "max_outstanding_claims": 150,
                    "max_requests_per_claim": 100,
                    "claim_timeout_s": 900
                },
                "app2": {
                    "api": "dummy",
                    "max_outstanding_claims": 1,
                    "max_requests_per_claim": 2,
                    "claim_timeout_s": 3
                }
            }
        }
        "#).unwrap();

        assert_eq!(
            deserialized, TurnipApiParams {
            // deadbeefDEADBEEFdeadbeefDEADBEEFdeadbeefDEADBEEFdeadbeefDEADBEEF
            key_base64: "ZGVhZGJlZWZERUFEQkVFRmRlYWRiZWVmREVBREJFRUZkZWFkYmVlZkRFQURCRUVGZGVhZGJlZWZERUFEQkVFRg==".to_string(),
            apps: HashMap::from([
                (
                    "app1".to_string(),
                    ApiAppParams {
                        api: ApiTarget::RundownV1,
                        max_outstanding_claims: MAX_OUTSTANDING_CLAIMS,
                        max_requests_per_claim: MAX_REQUESTS_PER_CLAIM,
                        claim_timeout_s: CLAIM_TIMEOUT_S,
                    }
                ),
                (
                    "app2".to_string(),
                    ApiAppParams {
                        api: ApiTarget::Dummy,
                        max_outstanding_claims: 1,
                        max_requests_per_claim: 2,
                        claim_timeout_s: 3,
                    }
                ),
            ])
        });
    }

    #[test]
    fn claims_must_have_unique_subjects() {
        let app_auth = test_env();

        let mut rands = HashSet::new();

        for _ in 0..MAX_OUTSTANDING_CLAIMS {
            let token = app_auth
                .generate_token("app1", 0)
                .expect("Should not fail to generate tokens");
            let token: TokenData<TurnipApiClaim> =
                jsonwebtoken::decode(&token, &app_auth.dec_key, &app_auth.validation)
                    .expect("Should be able to verify and decode the token");
            rands.insert(token.claims.sub);
        }

        assert_eq!(rands.len(), MAX_OUTSTANDING_CLAIMS);
    }

    #[test]
    fn must_only_allow_up_to_max_outstanding_claims() {
        let app_auth = test_env();

        // Make a bunch of initial claims
        for _ in 0..MAX_OUTSTANDING_CLAIMS {
            app_auth
                .generate_token("app1", 0)
                .expect("Should not fail to generate tokens");
        }

        // Make another claim, which should fail
        app_auth
            .generate_token("app1", 0)
            .expect_err("Should fail to make too many");
    }

    #[test]
    fn must_only_allow_up_to_max_outstanding_claims_multithreaded() {
        let app_auth = test_env();

        const N_THREADS: usize = 64;
        const N_GENERATIONS_PER_THREAD: usize = MAX_OUTSTANDING_CLAIMS / N_THREADS + 5;
        const N_TOTAL_CLAIMS: usize = N_GENERATIONS_PER_THREAD * N_THREADS;
        assert!(N_TOTAL_CLAIMS > MAX_OUTSTANDING_CLAIMS);

        let go_flag = AtomicBool::new(false);
        let n_successes = AtomicUsize::new(0);
        let n_fails = AtomicUsize::new(0);

        std::thread::scope(|scope| {
            let mut thread_handles = vec![];
            for _ in 0..N_THREADS {
                thread_handles.push(scope.spawn(|| {
                    while !go_flag.load(Ordering::Acquire) {}

                    for _ in 0..N_GENERATIONS_PER_THREAD {
                        match app_auth.generate_token("app1", 0) {
                            Ok(_) => n_successes.fetch_add(1, Ordering::AcqRel),
                            Err(_) => n_fails.fetch_add(1, Ordering::AcqRel),
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

        assert_eq!(n_successes.load(Ordering::Acquire), MAX_OUTSTANDING_CLAIMS);
        assert_eq!(
            n_fails.load(Ordering::Acquire),
            N_TOTAL_CLAIMS - MAX_OUTSTANDING_CLAIMS
        );
        let claims = &app_auth
            .app_runtimes
            .get_app_runtime("app1")
            .unwrap()
            .read()
            .unwrap()
            .outstanding_claims;
        assert_eq!(claims.len(), MAX_OUTSTANDING_CLAIMS);
    }

    #[test]
    fn must_allow_claim_to_expire_within_leeway() {
        let app_auth = test_env();

        let token = app_auth
            .generate_token("app1", 0)
            .expect("Should not fail to generate token");

        app_auth
            .validate_request(&token, ApiTarget::RundownV1, 0)
            .expect("Should be able to validate token immediately");
        // We should also be able to validate tokens up to and including timeout + the clock leeway
        for l in 0..TOKEN_TIMEOUT_LEEWAY {
            app_auth
                .validate_request(&token, ApiTarget::RundownV1, 0 + CLAIM_TIMEOUT_S + l)
                .expect("Should be able to validate token when within leeway");
        }
        // We should not be able to validate tokens after the timeout+leeway
        app_auth
            .validate_request(
                &token,
                ApiTarget::RundownV1,
                0 + CLAIM_TIMEOUT_S + TOKEN_TIMEOUT_LEEWAY + 1,
            )
            .expect_err("Should not be able to validate token when outside leeway");
    }

    #[test]
    fn must_disallow_mismatched_api_target() {
        let app_auth = test_env();

        let token = app_auth
            .generate_token("app1", 0)
            .expect("Should not fail to generate token");

        app_auth
            .validate_request(&token, ApiTarget::Dummy, 0)
            .expect_err("Should not validate token for mismatched API");
    }

    #[test]
    fn must_allow_new_tokens_once_others_have_expired() {
        let app_auth = test_env();

        const TOKEN_ISSUE_OFFSET: u64 = 1;
        assert!((MAX_OUTSTANDING_CLAIMS as u64) * TOKEN_ISSUE_OFFSET < CLAIM_TIMEOUT_S);
        for i in 0..MAX_OUTSTANDING_CLAIMS {
            app_auth
                .generate_token("app1", 0 + TOKEN_ISSUE_OFFSET * (i as u64))
                .expect("Should not fail to generate tokens");
        }

        let last_token_issue_time = (MAX_OUTSTANDING_CLAIMS as u64) * TOKEN_ISSUE_OFFSET;
        // So at this point we shouldn't expect to generate a token, all will still be outstanding
        app_auth
            .generate_token("app1", last_token_issue_time)
            .expect_err("Should fail to generate new token while all are valid");

        // We can generate tokens one-at-a-time as the previous ones decay.
        for i in 0..MAX_OUTSTANDING_CLAIMS {
            app_auth
                .generate_token(
                    "app1",
                    CLAIM_TIMEOUT_S + TOKEN_TIMEOUT_LEEWAY + TOKEN_ISSUE_OFFSET * (i as u64),
                )
                .expect("Should not fail to generate tokens second time around");
        }
    }

    #[test]
    fn must_allow_up_to_n_token_requests() {
        let app_auth = test_env();

        let token = app_auth
            .generate_token("app1", 0)
            .expect("Should not fail to generate token");

        for _ in 0..MAX_REQUESTS_PER_CLAIM {
            app_auth
                .validate_request(&token, ApiTarget::RundownV1, 1)
                .expect("Should not fail to use token");
        }

        app_auth
            .validate_request(&token, ApiTarget::RundownV1, 1)
            .expect_err("Should fail to use a token too many times");
    }

    #[test]
    fn must_allow_up_to_n_token_requests_multithreaded() {
        let app_auth = test_env();

        let token = app_auth
            .generate_token("app1", 0)
            .expect("Should not fail to generate token");

        const N_THREADS: u64 = 64;
        const N_TOKEN_REQUESTS_PER_THREAD: u64 = MAX_REQUESTS_PER_CLAIM / N_THREADS + 5;
        const N_TOTAL_REQUESTS: u64 = N_TOKEN_REQUESTS_PER_THREAD * N_THREADS;
        assert!(N_TOTAL_REQUESTS > MAX_REQUESTS_PER_CLAIM);

        let go_flag = AtomicBool::new(false);
        let n_successes = AtomicU64::new(0);
        let n_fails = AtomicU64::new(0);

        std::thread::scope(|scope| {
            let mut thread_handles = vec![];
            for _ in 0..N_THREADS {
                thread_handles.push(scope.spawn(|| {
                    while !go_flag.load(Ordering::Acquire) {}

                    for _ in 0..N_TOKEN_REQUESTS_PER_THREAD {
                        match app_auth.validate_request(&token, ApiTarget::RundownV1, 0) {
                            Ok(_) => n_successes.fetch_add(1, Ordering::AcqRel),
                            Err(_) => n_fails.fetch_add(1, Ordering::AcqRel),
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

        assert_eq!(n_successes.load(Ordering::Acquire), MAX_REQUESTS_PER_CLAIM);
        assert_eq!(
            n_fails.load(Ordering::Acquire),
            N_TOTAL_REQUESTS - MAX_REQUESTS_PER_CLAIM
        );
        let claims = &app_auth
            .app_runtimes
            .get_app_runtime("app1")
            .unwrap()
            .read()
            .unwrap()
            .outstanding_claims;
        assert_eq!(claims.len(), 1);
        assert_eq!(
            claims.get(&token).unwrap().requests.load(Ordering::Acquire),
            MAX_REQUESTS_PER_CLAIM
        );
    }

    #[test]
    fn overused_tokens_must_still_prevent_new_tokens() {
        // Need to make sure that if a token is used too much it still counts as an "outstanding" token
        // i.e. that you can't create a new token afterwards.
        // The purpose of limiting the outstanding tokens is rate limiting, and if you can constantly burn and create new ones
        // that bypasses it.
        let app_auth = test_env();

        for _ in 0..(MAX_OUTSTANDING_CLAIMS - 1) {
            app_auth
                .generate_token("app1", 0)
                .expect("Should not fail to generate tokens");
        }

        // Make the last token, so now at this point in time we should not be able to make anymore
        let final_token = app_auth
            .generate_token("app1", 0)
            .expect("Should not fail to generate token");
        app_auth
            .generate_token("app1", 0)
            .expect_err("Should be too many tokens");

        // Use the final_token up completely
        for _ in 0..MAX_REQUESTS_PER_CLAIM {
            app_auth
                .validate_request(&final_token, ApiTarget::RundownV1, 0)
                .expect("Should not fail to use token");
        }
        // The final token should be completely used up
        app_auth
            .validate_request(&final_token, ApiTarget::RundownV1, 0)
            .expect_err("Should be too many requests");

        // ...but the final token being used up shouldn't allow us to suddenly create another one
        app_auth
            .generate_token("app1", 0)
            .expect_err("Should still fail because the token is just overused and not expired");
    }
}
