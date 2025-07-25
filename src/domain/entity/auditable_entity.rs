use chrono::Utc;
use serde::{Deserialize, Serialize};
use crate::domain::entity::participant_data_entity::ParticipantData;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Auditable {
    pub created_by: Box<ParticipantData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<chrono::DateTime<Utc>>,
    pub updated_by: Box<ParticipantData>,
    pub active: bool
}

pub trait AuditableEntity {
    fn auditable_mut(&mut self) -> &mut Auditable;

    fn on_create(&mut self, by: ParticipantData) {
        let now = Utc::now();
        let mut aud = self.auditable_mut();
        aud.created_by = Box::new(by.clone());
        aud.updated_by = Box::new(by);
        aud.created_at = Some(now);
        aud.updated_at = Some(now);
        aud.active = true;
    }

    fn on_update(&mut self, by: ParticipantData) {
        let now = Utc::now();
        let mut aud = self.auditable_mut();
        aud.updated_by = Box::new(by);
        aud.updated_at = Some(now);
    }
}