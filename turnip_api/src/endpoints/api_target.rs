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
