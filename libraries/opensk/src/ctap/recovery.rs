use core::convert::TryInto;

// use crate::ctap::data_formats::CoseKey;
use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Write;
use crypto::backup;
use crypto::ecdh::{PubKey, SecKey};
use persistent_store::StoreError;
use sk_cbor::values::IntoCborValue;
use sk_cbor::{cbor_map, destructure_cbor_map, Value};

use crate::api::customization::{Customization, AAGUID_LENGTH};
use crate::api::private_key::PrivateKey;
use crate::ctap::{cbor_read, cbor_write};
use crate::env::Env;

use super::data_formats::{
    BackupData, PublicKeyCredentialDescriptor, RecoveryExtensionAction, RecoveryExtensionInput,
    RecoveryExtensionOutput,
};
use super::status_code::Ctap2StatusCode;
use super::storage::get_backup_data;
use super::storage::key::_RESERVED_CREDENTIALS;

//Takes RecoveryExtensionInput, processes it and returns the appropriate output.
pub fn process_recovery<E: Env>(
    inputs: RecoveryExtensionInput,
    env: &mut E,
    auth_data: Vec<u8>,
) -> Result<RecoveryExtensionOutput, Ctap2StatusCode> {
    let backup_data = cbor_read_backup(get_backup_data(env), env);
    if inputs.action == RecoveryExtensionAction::State {
        Ok(process_state_command(backup_data.recovery_state))
    } else if inputs.action == RecoveryExtensionAction::Generate {
        Ok(process_generate_command(env, inputs.rp_id, backup_data))
    } else if inputs.action == RecoveryExtensionAction::Recover {
        writeln!(env.write(), "Correct if branch").unwrap();
        process_recover_command::<E>(
            env,
            inputs.allow_list.unwrap(),
            inputs.rp_id,
            auth_data,
            backup_data,
        )
    } else {
        Err(Ctap2StatusCode::CTAP1_ERR_OTHER)
    }
}

//Retrieves the state and returns a RecoveryExtensionOutput struct with the appropriate information.
fn process_state_command(state: u64) -> RecoveryExtensionOutput {
    RecoveryExtensionOutput {
        action: RecoveryExtensionAction::State,
        state,
        creds: None,
        cred_id: None,
        sig: None,
    }
}

//Creates backup credentials for each stored backup device.
fn process_generate_command<E: Env>(
    env: &mut E,
    rp_id: String,
    backup_data: BackupData,
) -> RecoveryExtensionOutput {
    let creds = Some(process_recovery_seeds(
        backup_data.recovery_seeds,
        env,
        rp_id,
    ));
    RecoveryExtensionOutput {
        action: RecoveryExtensionAction::Generate,
        state: backup_data.recovery_state,
        creds,
        cred_id: None,
        sig: None,
    }
}

//Creates credential data for each recovery seed stored on this device.
fn process_recovery_seeds<E: Env>(
    seed_list: Vec<(u8, [u8; AAGUID_LENGTH], PubKey)>,
    env: &mut E,
    rp_id: String,
) -> Vec<Value> {
    let mut creds = Vec::new();
    for seed in seed_list.iter() {
        let att_cred_data = process_recovery_seed(seed.clone(), env, rp_id.clone());
        if att_cred_data.is_ok() {
            creds.push(att_cred_data.unwrap().into_cbor_value());
        }
    }
    creds
}

//Creates attCredData for one recovery seed.
fn process_recovery_seed<E: Env>(
    seed: (u8, [u8; AAGUID_LENGTH], PubKey),
    env: &mut E,
    rp_id: String,
) -> Result<Vec<u8>, Ctap2StatusCode> {
    if seed.0 != 0 {
        Err(Ctap2StatusCode::CTAP2_ERR_UNSUPPORTED_ALGORITHM)
    } else {
        let (credential_id, public_key) = make_credential(seed.clone(), env, rp_id);
        writeln!(env.write(), "Credential ID: {:?}", credential_id).unwrap();
        let mut public_key_bytes = [0u8; 65];
        public_key.to_bytes_uncompressed(&mut public_key_bytes);
        let mut att_cred_data = seed.1.to_vec();
        att_cred_data.extend(vec![0x00, credential_id.len() as u8]);
        att_cred_data.extend(credential_id);
        att_cred_data.extend_from_slice(&public_key_bytes);
        Ok(att_cred_data)
    }
}

//Gets credential for one seed.
fn make_credential<E: Env>(
    seed: (u8, [u8; AAGUID_LENGTH], PubKey),
    env: &mut E,
    rp_id: String,
) -> ([u8; 82], PubKey) {
    let (cred_id, public_key) = backup::calc_cred_id(rp_id, env.rng(), seed.2);
    // let cred = [08; 81];
    let mut full_cred_id = [08; 82];
    full_cred_id[0] = seed.0;
    full_cred_id[1..].copy_from_slice(&cred_id);
    let mut bytes = [0u8; 65];
    public_key.to_bytes_uncompressed(&mut bytes);
    writeln!(env.write(), "Public key from backup protocol: {:x?}", bytes).unwrap();
    (full_cred_id, public_key)
}

//Handles the logic of adding the alg byte to the beginning of a credential_id
fn make_full_cred_id(alg: u8, cred_id: [u8; 81]) -> [u8; 82] {
    let mut full_cred_id = [08; 82];
    full_cred_id[0] = alg;
    full_cred_id[1..].copy_from_slice(&cred_id);
    full_cred_id
}

//Processes backup credential for account recovery.
fn process_recover_command<E: Env>(
    env: &mut E,
    allow_credentials: Vec<PublicKeyCredentialDescriptor>,
    rp_id: String,
    auth_data: Vec<u8>,
    backup_data: BackupData,
) -> Result<RecoveryExtensionOutput, Ctap2StatusCode> {
    writeln!(env.write(), "Entered process_recover_command").unwrap();
    let mut sec_key_bytes: [u8; 32] = [08; 32];
    backup_data.secret_key.to_bytes(&mut sec_key_bytes);
    writeln!(env.write(), "Secret_Key_Bytes: {:?}", sec_key_bytes).unwrap();
    let credential_ids = process_allow_credentials(allow_credentials);
    writeln!(env.write(), "credential_ids: {:?}", credential_ids).unwrap();
    if let Some((secret_key, credential_id)) =
        get_credential_pair(env, credential_ids, rp_id, sec_key_bytes)
    {
        let mut signing_key_bytes = [0u8; 32];
        secret_key.to_bytes(&mut signing_key_bytes);
        let signing_key = PrivateKey::new_ecdsa_from_bytes(&mut signing_key_bytes)
            .expect("Couldn't get PrivatKey from bytes, recover.rs, process_recover_command");
        writeln!(
            env.write(),
            "Pub_key: {:x?}",
            signing_key.get_pub_key::<E>().unwrap()
        )
        .unwrap();
        writeln!(env.write(), "auth_data: {:x?}", auth_data.as_slice()).unwrap();
        let sig = signing_key.sign_and_encode::<E>(&auth_data).unwrap();
        let cred_id = make_full_cred_id(0, credential_id).to_vec();
        Ok(RecoveryExtensionOutput {
            action: RecoveryExtensionAction::Recover,
            state: backup_data.recovery_state,
            creds: None,
            cred_id: Some(cred_id),
            sig: Some(sig),
        })
    } else {
        Err(Ctap2StatusCode::CTAP2_ERR_NO_CREDENTIALS)
    }
}

//Processes allow_credentials and returns a list of isolated credential_ids.
fn process_allow_credentials(
    allow_credentials: Vec<PublicKeyCredentialDescriptor>,
) -> Vec<[u8; 81]> {
    let mut credential_ids = Vec::new();
    for cred in allow_credentials.iter() {
        if cred.key_id[0] == 0 {
            let cred_id: [u8; 81] = cred.key_id[1..].try_into().unwrap();
            credential_ids.push(cred_id);
        }
    }
    credential_ids
}

//Gets the recovery credential_id and private key, formats the private_key as a SecKey, and returns them.
fn get_credential_pair<E: Env>(
    env: &mut E,
    credential_list: Vec<[u8; 81]>,
    rp_id: String,
    sec_key_bytes: [u8; 32],
) -> Option<(SecKey, [u8; 81])> {
    let credential_option = backup::confirm_cred_ids(credential_list, rp_id, sec_key_bytes);
    writeln!(env.write(), "Passed Brennan's stuff").unwrap();
    if credential_option.is_some() {
        writeln!(env.write(), "Correct if branch").unwrap();
        let credential = credential_option.unwrap();
        let mut private_key_bytes = [0u8; 32];
        credential.0.to_bytes(&mut private_key_bytes);
        let private_key = SecKey::from_bytes(&private_key_bytes).unwrap();
        // let private_key = PrivateKey::new_ecdsa_from_bytes(&private_key_bytes).unwrap();
        Some((private_key, credential.1))
    } else {
        None
    }
}

//Writes a BackupData struct to a Vec<u8> in cbor format.
pub fn cbor_backups(backup_data: BackupData) -> Vec<u8> {
    // let mut public = [08; 65];
    // backup_data.public_key.to_bytes_uncompressed(&mut public);
    // let mut secret = [08; 32];
    // backup_data.secret_key.to_bytes(&mut secret);
    // let wrap_key = env.key_store().wrap_key::<E>().unwrap();
    let mut secret: [u8; 32] = [0u8; 32];
    backup_data.secret_key.to_bytes(&mut secret);
    // let secret = backup_data
    //     .secret_key
    //     .to_cbor::<E>(env.rng(), &wrap_key)
    //     .unwrap();
    let recovery_seeds = cbor_write_recovery_seeds(backup_data.recovery_seeds);
    let cbor_value =
        cbor_map! {0x01 => secret, 0x02 => backup_data.recovery_state, 0x03 => recovery_seeds};
    let mut bytes: Vec<u8> = Vec::new();
    cbor_write(cbor_value, &mut bytes).expect("Couldn't write backup data");
    bytes.to_owned()
}

//Takes a vector of cbor data and returns a BackupData struct with the cbor data.
pub fn cbor_read_backup<E: Env>(data: Option<Vec<u8>>, env: &mut E) -> BackupData {
    writeln!(env.write(), "Working at start of cbor_read_backup").unwrap();
    // let backup = data.unwrap().into_cbor_value();
    let backup = cbor_read(&data.unwrap().as_slice()).unwrap();
    writeln!(env.write(), "Working after converting to cbor value").unwrap();
    let map = backup.extract_map().unwrap();
    writeln!(env.write(), "Working after extracting a map").unwrap();
    destructure_cbor_map! {
        let {
            0x01 => secret,
            0x02 => state,
            0x03 => seeds,
        } = map;
    }
    writeln!(
        env.write(),
        "Working after destructuring cbor map, secret: {:?}, state {:?}",
        secret,
        state,
    )
    .unwrap();
    let secret_key_cbor = secret.unwrap();
    let secret_key_bytes: [u8; 32] = secret_key_cbor
        .extract_byte_string()
        .expect("Couldn't get byte string from secret_key_cbor, recovery.rs, cbor_read_backup")
        .as_slice()
        .try_into()
        .expect("Couldn't get byte string from secret_key_cbor, recovery.rs, cbor_read_backup");
    writeln!(env.write(), "Working after unwrapping secret").unwrap();
    let recovery_state = state.unwrap().extract_unsigned().unwrap();
    writeln!(env.write(), "Working after extracting state").unwrap();
    let recovey_seeds_cbor = seeds.unwrap().extract_array().unwrap();
    writeln!(env.write(), "Working after extracting array").unwrap();
    let recovery_seeds = cbor_read_recovery_seeds(recovey_seeds_cbor);
    writeln!(env.write(), "Working after read_recovery_seeds").unwrap();
    let secret_key = SecKey::from_bytes(&secret_key_bytes)
        .expect("Couldn't convert bytes to SecKey, recovery.rs, cbor_read_backup");
    // let secret_key =
    //     PrivateKey::from_cbor::<E>(&env.key_store().wrap_key::<E>().unwrap(), secret_key_cbor)
    //         .unwrap();
    writeln!(env.write(), "Working after extracting secret_key").unwrap();
    let public_key = secret_key.genpk();
    // let public_key = secret_key.get_pub_key::<E>().unwrap();
    // debug_ctap!(env, "Recovering backup public key: {:#?}", public_key);
    writeln!(
        env.write(),
        "Recovering backup public key: {:#?}, state: {:?}, seed: {:#?}",
        public_key,
        recovery_state,
        recovery_seeds
    )
    .unwrap();
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

//Store the BackupData for the key in the correct location
pub fn cbor_store_backup<E: Env>(backup_data: BackupData, env: &mut E) -> Result<(), StoreError> {
    let cbor_backup = cbor_backups(backup_data);
    env.store()
        .insert(_RESERVED_CREDENTIALS.start, &cbor_backup.as_slice())
}

//Process the export_recovery_seed command
pub fn export_recovery_seed<E: Env>(env: &mut E) -> Value {
    let backup_data = cbor_read_backup(get_backup_data(env), env);
    let aaguid = env.customization().aaguid();
    let seed = format_recovery_seed(backup_data, aaguid);
    cbor_write_recovery_seed(seed)
}

//Takes in the BackupData and aaguid for this authenticator and formats the recovery_seed
pub fn format_recovery_seed(
    backup_data: BackupData,
    aaguid: &[u8; AAGUID_LENGTH],
) -> (u8, [u8; AAGUID_LENGTH], PubKey) {
    (0, *aaguid, backup_data.public_key)
}

//Process the import_recovery_seed command
pub fn import_recovery_seed<E: Env>(
    cbor_seed_option: Option<Value>,
    env: &mut E,
) -> Result<(), StoreError> {
    if let Some(cbor_seed) = cbor_seed_option {
        let seed = cbor_read_recovery_seed(cbor_seed);
        let mut backup_data = cbor_read_backup(get_backup_data(env), env);
        writeln!(env.write(), "alg: {:?}", seed.0).unwrap();
        writeln!(env.write(), "aaguid: {:?}", seed.1).unwrap();
        writeln!(env.write(), "seed: {:?}", seed.2).unwrap();
        backup_data.recovery_seeds.push(seed);
        writeln!(
            env.write(),
            "recovery seeds list: {:?}",
            backup_data.recovery_seeds[0].2
        )
        .unwrap();
        backup_data.recovery_state += 1;
        cbor_store_backup(backup_data, env)
    } else {
        Err(StoreError::StorageError)
    }
}
