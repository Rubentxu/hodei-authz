use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum HrnError {
    #[error("Formato de HRN inválido: Se esperaban 6 partes separadas por ':'")]
    InvalidFormat,
    #[error("Prefijo de HRN inválido: debe empezar con 'hrn:'")]
    InvalidPrefix,
    #[error("Parte del recurso inválida: debe tener el formato 'tipo/id'")]
    InvalidResourcePart,
    #[error("Parte requerida del HRN no especificada: {0}")]
    MissingPart(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hrn {
    pub partition: String,
    pub service: String,
    pub region: String,
    pub tenant_id: String,
    pub resource_type: String,
    pub resource_id: String,
}

#[derive(Default)]
pub struct HrnBuilder {
    partition: Option<String>,
    service: Option<String>,
    region: Option<String>,
    tenant_id: Option<String>,
    resource_type: Option<String>,
    resource_id: Option<String>,
}

impl HrnBuilder {
    pub fn new() -> Self {
        Self {
            partition: Some("hodei".to_string()),
            region: Some("global".to_string()),
            ..Default::default()
        }
    }

    pub fn service(mut self, service: &str) -> Self {
        self.service = Some(service.to_string());
        self
    }

    pub fn tenant_id(mut self, tenant_id: &str) -> Self {
        self.tenant_id = Some(tenant_id.to_string());
        self
    }

    pub fn resource(mut self, resource_path: &str) -> Result<Self, HrnError> {
        if let Some((res_type, res_id)) = resource_path.split_once('/') {
            self.resource_type = Some(res_type.to_string());
            self.resource_id = Some(res_id.to_string());
            Ok(self)
        } else {
            Err(HrnError::InvalidResourcePart)
        }
    }

    pub fn build(self) -> Result<Hrn, HrnError> {
        Ok(Hrn {
            partition: self
                .partition
                .ok_or_else(|| HrnError::MissingPart("partition".into()))?,
            service: self
                .service
                .ok_or_else(|| HrnError::MissingPart("service".into()))?,
            region: self
                .region
                .ok_or_else(|| HrnError::MissingPart("region".into()))?,
            tenant_id: self
                .tenant_id
                .ok_or_else(|| HrnError::MissingPart("tenant_id".into()))?,
            resource_type: self
                .resource_type
                .ok_or_else(|| HrnError::MissingPart("resource_type".into()))?,
            resource_id: self
                .resource_id
                .ok_or_else(|| HrnError::MissingPart("resource_id".into()))?,
        })
    }
}

impl Hrn {
    pub fn builder() -> HrnBuilder {
        HrnBuilder::new()
    }
}

impl fmt::Display for Hrn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "hrn:{}:{}:{}:{}:{}/{}",
            self.partition,
            self.service,
            self.region,
            self.tenant_id,
            self.resource_type,
            self.resource_id
        )
    }
}

impl FromStr for Hrn {
    type Err = HrnError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("hrn:") {
            return Err(HrnError::InvalidPrefix);
        }
        let parts: Vec<&str> = s[4..].split(':').collect();
        if parts.len() != 5 {
            return Err(HrnError::InvalidFormat);
        }
        let resource_parts: Vec<&str> = parts[4].split('/').collect();
        if resource_parts.len() != 2 {
            return Err(HrnError::InvalidResourcePart);
        }
        Ok(Hrn {
            partition: parts[0].to_string(),
            service: parts[1].to_string(),
            region: parts[2].to_string(),
            tenant_id: parts[3].to_string(),
            resource_type: resource_parts[0].to_string(),
            resource_id: resource_parts[1].to_string(),
        })
    }
}

#[cfg(feature = "sqlx")]
impl sqlx::Type<sqlx::Postgres> for Hrn {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}

#[cfg(feature = "sqlx")]
impl<'q> sqlx::Encode<'q, sqlx::Postgres> for Hrn {
    fn encode_by_ref(&self, buf: &mut sqlx::postgres::PgArgumentBuffer) -> sqlx::encode::IsNull {
        let hrn_string = self.to_string();
        <String as sqlx::Encode<sqlx::Postgres>>::encode_by_ref(&hrn_string, buf)
    }
}

#[cfg(feature = "sqlx")]
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for Hrn {
    fn decode(
        value: sqlx::postgres::PgValueRef<'r>,
    ) -> Result<Self, Box<dyn std::error::Error + 'static + Send + Sync>> {
        let str_value = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        Ok(str_value.parse()?)
    }
}
