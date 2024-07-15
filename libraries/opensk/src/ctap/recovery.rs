use core::convert::TryInto;

use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use crypto::ecdh::PubKey;
use sk_cbor::values::IntoCborValue;
use sk_cbor::{cbor_map, destructure_cbor_map, Value};

use crate::api::customization::AAGUID_LENGTH;
use crate::api::key_store::KeyStore;
use crate::api::private_key::PrivateKey;
use crate::ctap::cbor_write;
use crate::env::Env;

use super::data_formats::{
    BackupData, RecoveryExtensionAction, RecoveryExtensionInput, RecoveryExtensionOutput,
};
use super::status_code::Ctap2StatusCode;

//Takes RecoveryExtensionInput, processes it and returns the appropriate output.
pub fn process_recovery<E: Env>(
    inputs: RecoveryExtensionInput,
    env: &mut E,
) -> Result<RecoveryExtensionOutput, Ctap2StatusCode> {
    if inputs.action == RecoveryExtensionAction::State {
        Ok(process_state_command(env))
    } else if inputs.action == RecoveryExtensionAction::Generate {
        Ok(process_generate_command())
    } else if inputs.action == RecoveryExtensionAction::Recover {
        Ok(process_recover_command())
    } else {
        Err(Ctap2StatusCode::CTAP1_ERR_OTHER)
    }
}

//Retrieves the state and returns a RecoveryExtensionOutput struct with the appropriate information.
fn process_state_command<E: Env>(env: &mut E) -> RecoveryExtensionOutput {
    let backup_data = cbor_read_backup(super::storage::_get_backup_data(env), env);
    RecoveryExtensionOutput {
        action: RecoveryExtensionAction::State,
        state: backup_data.recovery_state,
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
    let recovery_seeds = cbor_write_recovery_seeds(backup_data.recovery_seeds);
    let cbor_value = cbor_map! {"secret_key" => secret, "recovery_state" => backup_data.recovery_state, "recovery_seeds" => recovery_seeds};
    let mut bytes: Vec<u8> = Vec::new();
    cbor_write(cbor_value, &mut bytes).expect("Couldn't write backup data");
    bytes.to_owned()
}

//Takes a vector of cbor data and returns a BackupData struct with the cbor data.
pub fn cbor_read_backup<E: Env>(data: Option<Vec<u8>>, env: &mut E) -> BackupData {
    let backup = data.unwrap().into_cbor_value();
    let map = backup.extract_map().unwrap();
    destructure_cbor_map! {
        let {
            "recovery_seeds" => seeds,
            "recovery_state" => state,
            "secret_key" => secret,
        } = map;
    }
    let secret_key_cbor = secret.unwrap();
    let recovery_state = state.unwrap().extract_unsigned().unwrap();
    let recovey_seeds_cbor = seeds.unwrap().extract_array().unwrap();
    let recovery_seeds = cbor_read_recovery_seeds(recovey_seeds_cbor);
    let secret_key =
        PrivateKey::from_cbor::<E>(&env.key_store().wrap_key::<E>().unwrap(), secret_key_cbor)
            .unwrap();
    let public_key = secret_key.get_pub_key::<E>().unwrap();
    // debug_ctap!(env, "Recovering backup public key: {:#?}", public_key);
    BackupData {
        secret_key,
        public_key,
        recovery_state,
        recovery_seeds,
    }
}

// Encodes a recovery seed in cbor format.
pub fn cbor_write_recovery_seed(seed: (u8, [u8; AAGUID_LENGTH], PubKey)) -> Value {
    let mut public_key_bytes = [08; 65];
    seed.2.to_bytes_uncompressed(&mut public_key_bytes);
    cbor_map! {0 => [seed.0], 1 => seed.1, 2 => public_key_bytes}
}

// Takes a vector of recovery seeds and returns the vector encoded in cbor format.
pub fn cbor_write_recovery_seeds(seed_list: Vec<(u8, [u8; AAGUID_LENGTH], PubKey)>) -> Value {
    let mut encoded_seeds = Vec::new();
    for seed in seed_list.iter() {
        encoded_seeds.push(cbor_write_recovery_seed(seed.clone()));
    }
    encoded_seeds.into_cbor_value()
}

//Takes a cbor map and extracts a tuple containing a recovery seed.
pub fn cbor_read_recovery_seed(cbor_seed: Value) -> (u8, [u8; AAGUID_LENGTH], PubKey) {
    let map = cbor_seed.extract_map().unwrap();
    destructure_cbor_map! {
        let {
            0 => alg_option,
            1 => aaguid_option,
            2 => public_key_option,
        } = map;
    }
    let alg = alg_option.unwrap().extract_byte_string().unwrap()[0];
    let aaguid: [u8; AAGUID_LENGTH] = aaguid_option
        .unwrap()
        .extract_byte_string()
        .unwrap()
        .as_slice()
        .try_into()
        .expect("aaguid is incorrect length");
    let public_key = PubKey::from_bytes_uncompressed(
        public_key_option
            .unwrap()
            .extract_byte_string()
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    (alg, aaguid, public_key)
}

pub fn cbor_read_recovery_seeds(value_list: Vec<Value>) -> Vec<(u8, [u8; AAGUID_LENGTH], PubKey)> {
    let mut seed_list = Vec::new();
    for value in value_list {
        seed_list.push(cbor_read_recovery_seed(value));
    }
    seed_list
}
