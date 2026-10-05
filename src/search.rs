use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone)]
pub enum Needle {
    Name(String),
    Uri(url::Url),
    Uuid(uuid::Uuid, String),
}

impl Display for Needle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match &self {
            Self::Name(name) => name.clone(),
            Self::Uri(uri) => uri.to_string(),
            Self::Uuid(_, s) => s.clone(),
        };
        write!(f, "{value}")
    }
}

impl FromStr for Needle {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(uuid) = uuid::Uuid::parse_str(s) {
            return Ok(Needle::Uuid(uuid, s.to_string()));
        }
        if let Ok(url) = url::Url::parse(s) {
            if url.is_special() {
                return Ok(Needle::Uri(url));
            }
        }

        Ok(Needle::Name(s.to_string()))
    }
}
