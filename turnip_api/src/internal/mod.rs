use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        RwLock,
    },
};

use bimap::BiBTreeMap;
use jsonwebtoken::{DecodingKey, EncodingKey, TokenData};
use lazy_static::lazy_static;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use serde::{
    de::{Expected, Visitor},
    Deserialize, Serialize,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ApiTarget {
    RundownV1,
    #[cfg(test)]
    Dummy,
}

fn gen_api_target_to_str() -> BiBTreeMap<ApiTarget, &'static str> {
    let mut map = BiBTreeMap::new();
    map.insert(ApiTarget::RundownV1, "turnip_rundown/v1");
    #[cfg(test)]
    map.insert(ApiTarget::Dummy, "dummy");
    map
}

lazy_static! {
    static ref API_TARGET_STR: BiBTreeMap<ApiTarget, &'static str> = gen_api_target_to_str();
}

// TODO make this use a fast hash
type FastHashMap<L, R> = HashMap<L, R>;

impl Serialize for ApiTarget {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(API_TARGET_STR.get_by_left(self).unwrap())
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
                for str in API_TARGET_STR.right_values() {
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
                API_TARGET_STR
                    .get_by_right(v)
                    .ok_or(serde::de::Error::invalid_value(
                        serde::de::Unexpected::Str(v),
                        &ExpectedApiTarget,
                    ))
                    .copied()
            }
        }

        deserializer.deserialize_str(Visit)
    }
}

#[derive(Serialize, Deserialize)]
pub struct ApiTargetParams {}

#[derive(Serialize, Deserialize, Clone, Copy)]
pub struct ApiAppParams {
    /// The API target this app can use
    api: ApiTarget,
    /// The maximum amount of claims we will generate for this app at this time
    max_outstanding_claims: usize,
    /// The maximum amount of uses we allow per claim, to avoid one claim starving out all the others
    max_uses_per_claim: u64,
    /// The duration of time (in seconds) that new claims are given before they time out
    claim_timeout_s: u64,
}

#[derive(Serialize, Deserialize)]
pub struct TurnipApiParams {
    /// The key used to generate and validate API claims with the HMAC-SHA-256 scheme
    key_base64: String,
    targets: FastHashMap<ApiTarget, ApiTargetParams>,
    apps: FastHashMap<String, ApiAppParams>,
}

struct ApiTargetRuntimeInfo {}

type SecureRng = rand_chacha::ChaCha20Rng;

struct ApiAppRuntimeInfo {
    app_id: String,
    params: ApiAppParams,
    /// Mapping of (Claim GUID -> number of uses, timeout)
    outstanding_claims: RwLock<FastHashMap<String, OutstandingClaimInfo>>,
    /// Secure RNG used for generating the random Subject for each token
    rand: SecureRng,
}

impl ApiAppRuntimeInfo {
    fn use_token(&self, token_str: &str, target: ApiTarget) -> Result<(), ValidateTokenError> {
        if self.params.api != target {
            return Err(ValidateTokenError::ClaimTargetsIncorrectApi {
                api_claimed: self.params.api,
                api_requested: target,
            });
        }

        let claims = self
            .outstanding_claims
            .read()
            .expect("Poisoned lock somehow");
        if let Some(claim) = claims.get(token_str) {
            // TODO check those atomics
            match claim
                .uses
                .fetch_update(Ordering::Release, Ordering::Acquire, |x| {
                    if x >= self.params.max_uses_per_claim {
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
        let mut claims = self
            .outstanding_claims
            .write()
            .expect("Poisoned lock somehow");
        // If we know about more claims than the app supports at a time,
        // do a sweep to remove outdated ones and check again.
        // TODO: under heavy load doing a whole scan over and over might be too expensive. maintain a "next timeout" timestamp
        // and only scan once that's passed
        if claims.len() >= self.params.max_outstanding_claims {
            // Remove where timeout < timestamp, i.e. retain where timeout > timestamp
            // Use (timeout+leeway) to ensure that we leave things alive for long enough to handle clock skew
            claims.retain(|_token, outstanding_claim_info| {
                outstanding_claim_info.timeout + TOKEN_TIMEOUT_LEEWAY > utc_timestamp
            });
            if claims.len() >= self.params.max_outstanding_claims {
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
        claims.insert(
            encoded.clone(),
            OutstandingClaimInfo {
                uses: AtomicU64::new(0),
                timeout: claim.exp,
            },
        );
        Ok(encoded)
    }
}

struct OutstandingClaimInfo {
    uses: AtomicU64,
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

pub struct Apps {
    dec_key: jsonwebtoken::DecodingKey,
    enc_key: jsonwebtoken::EncodingKey,
    validation: jsonwebtoken::Validation,
    _targets: FastHashMap<ApiTarget, ApiTargetRuntimeInfo>,
    apps: FastHashMap<String, RwLock<ApiAppRuntimeInfo>>,
}
impl Apps {
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
            _targets: FastHashMap::from_iter(
                params
                    .targets
                    .into_iter()
                    .map(|(target, _target_params)| (target, ApiTargetRuntimeInfo {})),
            ),
            apps: FastHashMap::from_iter(params.apps.into_iter().map(|(app_key, app_params)| {
                (
                    app_key.clone(),
                    RwLock::new(ApiAppRuntimeInfo {
                        params: app_params,
                        outstanding_claims: RwLock::new(FastHashMap::new()),
                        rand: SecureRng::from_os_rng(),
                        app_id: app_key,
                    }),
                )
            })),
        }
    }

    /// Given a JWT token, validate it against the App ID it claims to have
    /// and what ApiTarget endpoint it's been sent to, and increment its uses
    pub fn validate_token(
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
        match self.apps.get(&token.claims.app_id) {
            Some(app) => {
                let app = app.read().expect("Poisoned lock somehow");
                app.use_token(token_str, target)
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
        match self.apps.get(app_id) {
            Some(app) => {
                let mut app = app.write().expect("Poisoned lock somehow");
                app.generate_token(key, utc_timestamp)
            }
            None => Err(GenerateTokenError::BadAppId),
        }
    }
    // TODO renew tokens?
}

#[cfg(test)]
pub mod test {
    use std::collections::HashSet;

    use jsonwebtoken::TokenData;

    use super::{
        ApiAppParams, ApiTarget, ApiTargetParams, Apps, FastHashMap, TurnipApiClaim,
        TurnipApiParams, TOKEN_TIMEOUT_LEEWAY,
    };

    const MAX_OUTSTANDING_CLAIMS: usize = 150;
    const MAX_USES_PER_CLAIM: u64 = 150;
    const CLAIM_TIMEOUT_S: u64 = 15 * 60;

    fn test_env() -> Apps {
        Apps::from_config(TurnipApiParams {
            // deadbeefDEADBEEFdeadbeefDEADBEEFdeadbeefDEADBEEFdeadbeefDEADBEEF
            key_base64: "ZGVhZGJlZWZERUFEQkVFRmRlYWRiZWVmREVBREJFRUZkZWFkYmVlZkRFQURCRUVGZGVhZGJlZWZERUFEQkVFRg==".to_string(),
            targets: FastHashMap::from([
                (ApiTarget::RundownV1, ApiTargetParams {
                })
            ]),
            apps: FastHashMap::from([
                (
                    "app1".to_string(),
                    ApiAppParams {
                        api: ApiTarget::RundownV1,
                        max_outstanding_claims: MAX_OUTSTANDING_CLAIMS,
                        max_uses_per_claim: MAX_USES_PER_CLAIM,
                        claim_timeout_s: CLAIM_TIMEOUT_S,
                    }
                )
            ])
        })
    }

    #[test]
    fn claims_must_have_unique_subjects() {
        let apps = test_env();

        let mut rands = HashSet::new();

        for _ in 0..MAX_OUTSTANDING_CLAIMS {
            let token = apps
                .generate_token("app1", 0)
                .expect("Should not fail to generate tokens");
            let token: TokenData<TurnipApiClaim> =
                jsonwebtoken::decode(&token, &apps.dec_key, &apps.validation)
                    .expect("Should be able to verify and decode the token");
            rands.insert(token.claims.sub);
        }

        assert_eq!(rands.len(), MAX_OUTSTANDING_CLAIMS);
    }

    #[test]
    fn must_only_allow_up_to_max_outstanding_claims() {
        let apps = test_env();

        // Make a bunch of initial claims
        for _ in 0..MAX_OUTSTANDING_CLAIMS {
            apps.generate_token("app1", 0)
                .expect("Should not fail to generate tokens");
        }

        // Make another claim, which should fail
        apps.generate_token("app1", 0)
            .expect_err("Should fail to make too many");
    }

    #[test]
    fn must_allow_claim_to_expire_within_leeway() {
        let apps = test_env();

        let token = apps
            .generate_token("app1", 0)
            .expect("Should not fail to generate token");

        apps.validate_token(&token, ApiTarget::RundownV1, 0)
            .expect("Should be able to validate token immediately");
        // We should also be able to validate tokens up to and including timeout + the clock leeway
        for l in 0..TOKEN_TIMEOUT_LEEWAY {
            apps.validate_token(&token, ApiTarget::RundownV1, 0 + CLAIM_TIMEOUT_S + l)
                .expect("Should be able to validate token when within leeway");
        }
        // We should not be able to validate tokens after the timeout+leeway
        apps.validate_token(
            &token,
            ApiTarget::RundownV1,
            0 + CLAIM_TIMEOUT_S + TOKEN_TIMEOUT_LEEWAY + 1,
        )
        .expect_err("Should not be able to validate token when outside leeway");
    }

    #[test]
    fn must_disallow_mismatched_api_target() {
        let apps = test_env();

        let token = apps
            .generate_token("app1", 0)
            .expect("Should not fail to generate token");

        apps.validate_token(&token, ApiTarget::Dummy, 0)
            .expect_err("Should not validate token for mismatched API");
    }

    #[test]
    fn must_allow_new_tokens_once_others_have_expired() {
        let apps = test_env();

        const TOKEN_ISSUE_OFFSET: u64 = 1;
        assert!((MAX_OUTSTANDING_CLAIMS as u64) * TOKEN_ISSUE_OFFSET < CLAIM_TIMEOUT_S);
        for i in 0..MAX_OUTSTANDING_CLAIMS {
            apps.generate_token("app1", 0 + TOKEN_ISSUE_OFFSET * (i as u64))
                .expect("Should not fail to generate tokens");
        }

        let last_token_issue_time = (MAX_OUTSTANDING_CLAIMS as u64) * TOKEN_ISSUE_OFFSET;
        // So at this point we shouldn't expect to generate a token, all will still be outstanding
        apps.generate_token("app1", last_token_issue_time)
            .expect_err("Should fail to generate new token while all are valid");

        // We can generate tokens one-at-a-time as the previous ones decay.
        for i in 0..MAX_OUTSTANDING_CLAIMS {
            apps.generate_token(
                "app1",
                CLAIM_TIMEOUT_S + TOKEN_TIMEOUT_LEEWAY + TOKEN_ISSUE_OFFSET * (i as u64),
            )
            .expect("Should not fail to generate tokens second time around");
        }
    }

    #[test]
    fn must_allow_up_to_n_token_usages() {
        let apps = test_env();

        let token = apps
            .generate_token("app1", 0)
            .expect("Should not fail to generate token");

        for _ in 0..MAX_USES_PER_CLAIM {
            apps.validate_token(&token, ApiTarget::RundownV1, 1)
                .expect("Should not fail to use token");
        }

        apps.validate_token(&token, ApiTarget::RundownV1, 1)
            .expect_err("Should fail to use a token too many times");
    }
    // TODO must_allow_up_to_n_token_usages_multithreaded
}
