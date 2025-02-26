use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;

#[derive(Clone, Debug, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum Sbom<'a> {
    V1_4(Cow<'a, serde_cyclonedx::cyclonedx::v_1_4::CycloneDx>),
    V1_5(Cow<'a, serde_cyclonedx::cyclonedx::v_1_5::CycloneDx>),
    V1_6(Cow<'a, serde_cyclonedx::cyclonedx::v_1_6::CycloneDx>),
}

impl Serialize for Sbom<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::V1_4(sbom) => sbom.serialize(serializer),
            Self::V1_5(sbom) => sbom.serialize(serializer),
            Self::V1_6(sbom) => sbom.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Sbom<'static> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // TODO: peek into the version, and select the correct version
        serde_cyclonedx::cyclonedx::v_1_6::CycloneDx::deserialize(deserializer)
            .map(|s| Self::V1_6(Cow::Owned(s)))
    }
}

macro_rules! attribute {
    ($name:ident => | $v:ident -> $ret:ty | $access:expr  ) => {
        pub fn $name(&self) -> $ret {
            match self {
                Self::V1_4($v) => $access,
                Self::V1_5($v) => $access,
                Self::V1_6($v) => $access,
            }
        }
    };
}

macro_rules! from {
    ( $($lt:lifetime,)? $src:ident, $name:ty) => {
        impl <$($lt,)? > From<$(& $lt)? serde_cyclonedx::cyclonedx::v_1_4::$src> for $name {
            fn from(value: $(& $lt)? serde_cyclonedx::cyclonedx::v_1_4::$src) -> Self {
                Self::V1_4(value)
            }
        }

        impl <$($lt,)? > From<$(& $lt)? serde_cyclonedx::cyclonedx::v_1_5::$src> for $name {
            fn from(value: $(& $lt)? serde_cyclonedx::cyclonedx::v_1_5::$src) -> Self {
                Self::V1_5(value)
            }
        }

        impl <$($lt,)? > From<$(& $lt)? serde_cyclonedx::cyclonedx::v_1_6::$src> for $name {
            fn from(value: $(& $lt)? serde_cyclonedx::cyclonedx::v_1_6::$src) -> Self {
                Self::V1_6(value)
            }
        }
    };
}

impl Sbom<'_> {
    attribute!(components => |sbom -> Option<Vec<Component>> | sbom
                .components
                .as_ref()
                .map(|c| c.iter().map(Into::into).collect()));

    attribute!(dependencies => |sbom -> Option<Vec<Dependency>> | sbom
                .dependencies
                .as_ref()
                .map(|c| c.iter().map(Into::into).collect()));
}

impl From<serde_cyclonedx::cyclonedx::v_1_4::CycloneDx> for Sbom<'static> {
    fn from(value: serde_cyclonedx::cyclonedx::v_1_4::CycloneDx) -> Self {
        Self::V1_4(Cow::Owned(value))
    }
}

impl From<serde_cyclonedx::cyclonedx::v_1_5::CycloneDx> for Sbom<'static> {
    fn from(value: serde_cyclonedx::cyclonedx::v_1_5::CycloneDx) -> Self {
        Self::V1_5(Cow::Owned(value))
    }
}

impl From<serde_cyclonedx::cyclonedx::v_1_6::CycloneDx> for Sbom<'static> {
    fn from(value: serde_cyclonedx::cyclonedx::v_1_6::CycloneDx) -> Self {
        Self::V1_6(Cow::Owned(value))
    }
}

impl<'a> From<&'a serde_cyclonedx::cyclonedx::v_1_4::CycloneDx> for Sbom<'a> {
    fn from(value: &'a serde_cyclonedx::cyclonedx::v_1_4::CycloneDx) -> Self {
        Self::V1_4(Cow::Borrowed(value))
    }
}

impl<'a> From<&'a serde_cyclonedx::cyclonedx::v_1_5::CycloneDx> for Sbom<'a> {
    fn from(value: &'a serde_cyclonedx::cyclonedx::v_1_5::CycloneDx) -> Self {
        Self::V1_5(Cow::Borrowed(value))
    }
}

impl<'a> From<&'a serde_cyclonedx::cyclonedx::v_1_6::CycloneDx> for Sbom<'a> {
    fn from(value: &'a serde_cyclonedx::cyclonedx::v_1_6::CycloneDx) -> Self {
        Self::V1_6(Cow::Borrowed(value))
    }
}

// component

#[derive(Clone, Debug, PartialEq)]
pub enum Component<'a> {
    V1_4(&'a serde_cyclonedx::cyclonedx::v_1_4::Component),
    V1_5(&'a serde_cyclonedx::cyclonedx::v_1_5::Component),
    V1_6(&'a serde_cyclonedx::cyclonedx::v_1_6::Component),
}

from!('a, Component,  Component<'a>);

impl<'a> Component<'a> {
    attribute!(bom_ref => |c -> Option<&'a str> | c.bom_ref.as_deref());
}

// dependency

#[derive(Clone, Debug, PartialEq)]
pub enum Dependency<'a> {
    V1_4(&'a serde_cyclonedx::cyclonedx::v_1_4::Dependency),
    V1_5(&'a serde_cyclonedx::cyclonedx::v_1_5::Dependency),
    V1_6(&'a serde_cyclonedx::cyclonedx::v_1_6::Dependency),
}

from!('a, Dependency,  Dependency<'a>);

impl Dependency<'_> {
    pub fn r#ref(&self) -> &str {
        match self {
            Self::V1_4(dep) => &dep.ref_,
            Self::V1_5(dep) => dep.ref_.as_str().unwrap_or_default(),
            Self::V1_6(dep) => &dep.ref_,
        }
    }

    pub fn dependencies(&self) -> Option<Vec<&str>> {
        match self {
            Self::V1_4(dep) => dep
                .depends_on
                .as_ref()
                .map(|deps| deps.iter().map(|s| s.as_str()).collect()),
            Self::V1_5(dep) => dep
                .depends_on
                .as_ref()
                .map(|deps| deps.iter().flat_map(|s| s.as_str()).collect()),
            Self::V1_6(dep) => dep
                .depends_on
                .as_ref()
                .map(|deps| deps.iter().map(|s| s.as_str()).collect()),
        }
    }
}
