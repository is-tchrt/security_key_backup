use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use sk_cbor::cbor_map;

use crate::api::key_store::KeyStore;
use crate::ctap::cbor_write;
use crate::env::Env;

use super::data_formats::{
    BackupData, RecoveryExtensionAction, RecoveryExtensionInput, RecoveryExtensionOutput,
};
use super::status_code::Ctap2StatusCode;

//Takes RecoveryExtensionInput, processes it and returns the appropriate output.
pub fn process_recovery(
    inputs: RecoveryExtensionInput,
) -> Result<RecoveryExtensionOutput, Ctap2StatusCode> {
    if inputs.action == RecoveryExtensionAction::State {
        Ok(process_state_command())
    } else if inputs.action == RecoveryExtensionAction::Generate {
        Ok(process_generate_command())
    } else if inputs.action == RecoveryExtensionAction::Recover {
        Ok(process_recover_command())
    } else {
        Err(Ctap2StatusCode::CTAP1_ERR_OTHER)
    }
}

//Retrieves the state and returns a RecoveryExtensionOutput struct with the appropriate information.
fn process_state_command() -> RecoveryExtensionOutput {
    RecoveryExtensionOutput {
        action: RecoveryExtensionAction::State,
        state: 0,
        creds: None,
        cred_id: None,
        sig: None,
    }
}

//Creates backup credentials for each stored backup device.
fn process_generate_command() -> RecoveryExtensionOutput {
    RecoveryExtensionOutput {
        action: RecoveryExtensionAction::Generate,
        state: 0,
        creds: None,
        cred_id: None,
        sig: None,
    }
}

//Processes backup credential for account recovery.
fn process_recover_command() -> RecoveryExtensionOutput {
    RecoveryExtensionOutput {
        action: RecoveryExtensionAction::Recover,
        state: 0,
        creds: None,
        cred_id: None,
        sig: None,
    }
}

pub fn cbor_backups<E: Env>(backup_data: BackupData, env: &mut E) -> Vec<u8> {
    // let mut public = [08; 65];
    // backup_data.public_key.to_bytes_uncompressed(&mut public);
    // let mut secret = [08; 32];
    // backup_data.secret_key.to_bytes(&mut secret);
    let wrap_key = env.key_store().wrap_key::<E>().unwrap();
    let secret = backup_data
        .secret_key
        .to_cbor::<E>(env.rng(), &wrap_key)
        .unwrap();
    let cbor_value = cbor_map! {"secret_key" => secret, "public_key" => backup_data.public_key};
    let mut bytes: Vec<u8> = Vec::new();
    cbor_write(cbor_value, &mut bytes).expect("Couldn't write backup data");
    bytes.to_owned()
}
