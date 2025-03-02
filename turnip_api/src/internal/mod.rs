use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        RwLock,
    },
};

use bimap::BiHashMap;
use jsonwebtoken::{DecodingKey, EncodingKey, TokenData};
use lazy_static::lazy_static;
use serde::{
    de::{Expected, Visitor},
    Deserialize, Serialize,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ApiTarget {
    RundownV1,
}

fn gen_api_target_to_str() -> BiHashMap<ApiTarget, &'static str> {
    let mut map = BiHashMap::new();
    map.insert(ApiTarget::RundownV1, "turnip_rundown/v1");
    map
}

lazy_static! {
    static ref API_TARGET_STR: BiHashMap<ApiTarget, &'static str> = gen_api_target_to_str();
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
                todo!()
            }
        }
        struct Visit;
        impl<'de> Visitor<'de> for Visit {
            type Value = ApiTarget;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                todo!()
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
struct ApiTargetParams {
    /// The key used to generate and validate API claims with the HMAC-SHA-256 scheme
    key_base64: String,
}

#[derive(Serialize, Deserialize)]
struct ApiAppParams {
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
struct TurnipApiParams {
    targets: FastHashMap<ApiTarget, ApiTargetParams>,
    apps: FastHashMap<String, ApiAppParams>,
}

struct ApiTargetRuntimeInfo {
    dec_key: jsonwebtoken::DecodingKey,
    enc_key: jsonwebtoken::EncodingKey,
}

struct ApiAppRuntimeInfo {
    params: ApiAppParams,
    /// Mapping of (Claim GUID -> number of uses, timeout)
    outstanding_claims: RwLock<FastHashMap<String, OutstandingClaimInfo>>,
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
    sub: u64,
}

enum ValidateTokenError {
    UnsupportedApiTarget(ApiTarget),
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

enum GenerateTokenError {
    UnsupportedApiTarget(ApiTarget),
    JwtError(jsonwebtoken::errors::Error),
    BadAppId,
    AppHasTooManyOutstandingClaims,
}

const TOKEN_ALGORITHM: jsonwebtoken::Algorithm = jsonwebtoken::Algorithm::HS256;

struct Apps {
    validation: jsonwebtoken::Validation,
    targets: FastHashMap<ApiTarget, ApiTargetRuntimeInfo>,
    apps: FastHashMap<String, ApiAppRuntimeInfo>,
}
impl Apps {
    pub fn from_config(params: TurnipApiParams) -> Self {
        let mut validation = jsonwebtoken::Validation::new(TOKEN_ALGORITHM);
        validation.leeway = 30;
        validation.set_audience(&[TURNIP_API_AUD]);
        validation.set_required_spec_claims(todo!());

        Self {
            validation,
            targets: FastHashMap::from_iter(params.targets.into_iter().map(
                |(target, target_params)| {
                    (
                        target,
                        ApiTargetRuntimeInfo {
                            dec_key: DecodingKey::from_base64_secret(&target_params.key_base64)
                                .expect("Failed to decode key base64"),
                            enc_key: EncodingKey::from_base64_secret(&target_params.key_base64)
                                .expect("Failed to decode key base64"),
                        },
                    )
                },
            )),
            apps: FastHashMap::from_iter(params.apps.into_iter().map(|(app_key, app_params)| {
                (
                    app_key,
                    ApiAppRuntimeInfo {
                        params: app_params,
                        outstanding_claims: RwLock::new(FastHashMap::new()),
                    },
                )
            })),
        }
    }

    /// Given a JWT token, validate it against the App ID it claims to have
    /// and what ApiTarget endpoint it's been sent to, and increment its uses
    pub fn validate_token(&self, token: &str, target: ApiTarget) -> Result<(), ValidateTokenError> {
        let key = &self
            .targets
            .get(&target)
            .ok_or(ValidateTokenError::UnsupportedApiTarget(target))?
            .dec_key;
        let claim: TokenData<TurnipApiClaim> = jsonwebtoken::decode(token, key, &self.validation)
            .map_err(|err| match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                ValidateTokenError::ClaimHasExpired
            }
            jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                ValidateTokenError::ClaimHasBadAudience
            }
            _ => ValidateTokenError::JwtError(err),
        })?;
        match self.apps.get(&claim.claims.app_id) {
            Some(app) => {
                if app.params.api != target {
                    return Err(ValidateTokenError::ClaimTargetsIncorrectApi {
                        api_claimed: app.params.api,
                        api_requested: target,
                    });
                }

                let claims = app
                    .outstanding_claims
                    .read()
                    .expect("Poisoned lock somehow");
                if let Some(claim) = claims.get(token) {
                    // TODO check those atomics
                    match claim
                        .uses
                        .fetch_update(Ordering::Release, Ordering::Acquire, |x| {
                            if x >= app.params.max_uses_per_claim {
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
            None => Err(ValidateTokenError::ClaimHasInvalidAppId),
        }
    }
    /// Given an App ID, generate a new token for it (if it has spare outstanding claims)
    pub fn generate_token(&self, app_id: &str) -> Result<String, GenerateTokenError> {
        match self.apps.get(app_id) {
            Some(app) => {
                let key = &self
                    .targets
                    .get(&app.params.api)
                    .ok_or(GenerateTokenError::UnsupportedApiTarget(app.params.api))?
                    .enc_key;

                let claims = app.outstanding_claims.get_mut().expect("Poisoned lock somehow");
                // If we know about more claims than the app supports at a time,
                // do a sweep to remove outdated ones and check again.
                // TODO: under heavy load doing a whole scan would be too expensive. maintain a "next timeout" timestamp
                // and only scan once that's passed
                if claims.len() >= app.params.max_outstanding_claims {
                    let timestamp = todo!();
                    // Remove where timeout < timestamp, i.e. retain where timeout > timestamp
                    // Use (timeout+leeway) to ensure that we leave things alive for long enough to handle clock skew
                    claims.retain(|_token, outstanding_claim_info| outstanding_claim_info.timeout + self.validation.leeway > timestamp);
                    if claims.len() >= app.params.max_outstanding_claims {
                        return Err(GenerateTokenError::AppHasTooManyOutstandingClaims)
                    }
                }

                // We have enough room, generate a new claim
                let claim = TurnipApiClaim {
                    app_id: app_id.to_owned(),
                    exp: todo!("get time + ") + app.params.claim_timeout_s,
                    aud: TURNIP_API_AUD.to_string(),
                    sub: todo!("random 64-bits"),
                };
                let encoded = jsonwebtoken::encode(&jsonwebtoken::Header::new(TOKEN_ALGORITHM), &claim, &key).map_err(|err| {
                    GenerateTokenError::JwtError(err)
            })?;
                claims.insert(encoded, OutstandingClaimInfo {
                    uses: AtomicU64::new(0),
                    timeout: claim.exp,
                });
                Ok(encoded)
            }
            None => Err(GenerateTokenError::BadAppId)
        }
    }
    // TODO renew tokens?
}
