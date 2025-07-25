use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct RandomizationResponse {
    assignments: Vec<bool>,
    proof: String,
    public_inputs: String,
}

impl RandomizationResponse {
    pub fn new(
        assignments: Vec<bool>,
        proof: Vec<u8>,
        public_inputs: Vec<u8>,
    ) -> Self {
        Self {
            assignments,
            proof: base64::encode(proof),
            public_inputs: base64::encode(public_inputs),
        }
    }

    pub fn get_proof_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::decode(&self.proof)
    }

    pub fn get_public_inputs_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::decode(&self.public_inputs)
    }
}