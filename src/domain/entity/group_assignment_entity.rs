use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use crate::infrastructure::error::error_handler::{AppError, InfrastructureError};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum GroupAssignment {
    Treatment,   // grupo que recebe o fármaco/intervenção
    Control,     // grupo placebo ou controle padrão
    None,        // não alocado (ou ainda cego no banco em claro)
}

impl fmt::Display for GroupAssignment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            GroupAssignment::Treatment => "Treatment",
            GroupAssignment::Control   => "Control",
            GroupAssignment::None      => "None",
        })
    }
}

impl FromStr for GroupAssignment {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "treatment" => Ok(GroupAssignment::Treatment),
            "control"   => Ok(GroupAssignment::Control),
            "none"      | "" => Ok(GroupAssignment::None),
            _ => Err(()),
        }
    }
}

impl GroupAssignment {
    pub fn from_str_lossy(s: &str) -> Self {
        Self::from_str(s).unwrap_or(GroupAssignment::None)
    }

    pub fn parse(s: &str) -> Result<Self, ()> {
        Self::from_str(s)
    }

    pub fn from_encrypted(s: &str) -> Result<Self, AppError> {
        Self::from_str(s)
            .map_err(|_| InfrastructureError::DataError.into())
    }
}