/////////////////////////////This file implements the Yubico Backup functionality for the key./////////////////////////////

//crates
use crate::alloc::vec::Vec;
use alloc::string::String;
use rand_core::RngCore;

//this section allows the use of libraries in the folders above
use super::{ec, ecdsa, hkdf, hmac, Hash256};
use crate::ecdh::{PubKey, SecKey};
use crate::sha256::Sha256;

/////////////////////////////utility functions/////////////////////////////

//generates an ephemeral pair of keys
pub fn generate_ephemeral_pair<R>(rng: &mut R) -> (SecKey, PubKey)
where
    R: RngCore,
{
    let sk = SecKey::gensk(rng);
    let pk = sk.genpk();
    let key_pair = (sk, pk);
    key_pair
}

//creates the cred_key
pub fn cred_key(sec_key: &SecKey, pub_key: &PubKey) -> [u8; 32] {
    let shared_secret = sec_key.exchange_x(&pub_key);

    //salt should be empty
    let salt = [0u8; 32];
    let mut hkdf_output = [0u8; 32];
    let info = "webauthn.recovery.cred_key".as_bytes();
    hkdf::hkdf_256::<Sha256>(&shared_secret, &salt, &info, &mut hkdf_output);
    hkdf_output
}

//creates a mac key
pub fn mac_key(sec_key: &SecKey, pub_key: &PubKey) -> [u8; 32] {
    let shared_secret = sec_key.exchange_x(&pub_key);

    //salt should be empty
    let salt = [0u8; 32];
    let mut hkdf_output = [0u8; 32];
    let info = "webauthn.recovery.mac_key".as_bytes();
    hkdf::hkdf_256::<Sha256>(&shared_secret, &salt, &info, &mut hkdf_output);
    hkdf_output
}

//this generates the public key that the RP uses to validate the backup
pub fn backup_pk(cred_key: &[u8; 32], pub_key: &PubKey) -> PubKey {
    //makes B

    //this converts cred_id into the proper format to mul by the generator(G) of the EC
    let cred_int = ec::int256::Int256::from_bin(cred_key);
    let cred_as_exponent = ec::exponent256::ExponentP256::from_int_checked(cred_int).unwrap();
    let mul_by_g = ec::point::PointProjective::scalar_base_mul(&cred_as_exponent);

    //conversion to x and y (preliminary step to add points in EC)
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    pub_key.to_coordinates(&mut x, &mut y);
    let backup_public_key_ecdsa = ecdsa::PubKey::from_coordinates(&x, &y);

    // add the point we multiplied by G to the public key
    let credential_public_as_projective =
        mul_by_g.add_mixed(&backup_public_key_ecdsa.unwrap().get_point().to_affine());

    //convert to a point
    let affine = credential_public_as_projective.to_affine();
    let point = ec::point::PointP256::from_affine(&affine);

    //set the x and y coordinates (allows us to convert back to a pubKey)
    point.getx().to_int().to_bin(&mut x);
    point.gety().to_int().to_bin(&mut y);

    //return a public key
    PubKey::from_coordinates(&x, &y).unwrap()
}

//makes a [u8; 81] credential id that is given to the RP for further verification of legit backup keys
pub fn make_cred_id(pub_key: PubKey, mac_key: [u8; 32], rp_id: String) -> [u8; 81] {
    //converts pub_key to bytes
    let mut pub_key_bytes = [0u8; 65];
    pub_key.to_bytes_uncompressed(&mut pub_key_bytes);

    //cred id is made up of three parts, input_mac, mac_output, pub_key
    //make the input
    let mut input_mac = [0u8; 65 + 32];
    let rp_id_hash = <Sha256 as Hash256>::hash(rp_id.as_bytes());
    input_mac[..65].copy_from_slice(&pub_key_bytes); // Copy public key bytes
    input_mac[65..].copy_from_slice(&rp_id_hash);

    //calc mac
    let mut mac_output = [0u8; 32];
    hmac::hmac_256::<Sha256>(&mac_key, input_mac.as_slice(), &mut mac_output);

    //put it all together into cred_id
    let mut cred_id = [0u8; 81]; // Initialize cred_id array
    cred_id[..65].copy_from_slice(&pub_key_bytes); // Copy public key bytes
    cred_id[65..].copy_from_slice(&mac_output[..16]); // Copy first 16 bytes of MAC
    cred_id
}

//creates the private key that corresponds with the public key given to the RP
pub fn backup_sk(cred_key: [u8; 32], sec_key_bytes: [u8; 32]) -> SecKey {
    //makes b
    let sec_key = SecKey::from_bytes(&sec_key_bytes).unwrap();
    let scalar = sec_key.to_exponent().to_int();
    let mod_n = ec::exponent256::ExponentP256::modn(scalar);
    let cred_int = ec::int256::Int256::from_bin(&cred_key);
    let cred_ex = ec::exponent256::ExponentP256::from_int_checked(cred_int).unwrap();
    let test = cred_ex.to_int().modd(&mod_n.to_int());
    let test_result = ec::exponent256::ExponentP256::from_int_checked(test).unwrap();
    let test_sec_key = Some(SecKey {
        a: test_result.non_zero().unwrap(),
    })
    .unwrap();
    test_sec_key
    // let result = &cred_ex * &mod_n;
    // let sec_key = Some(SecKey {
    //     a: result.non_zero().unwrap(),
    // })
    // .unwrap();
    // sec_key
}

/////////////////////////////Implementing stage 2/////////////////////////////

//creates a tuple of a cred_id and a public key that are passed to the RP for proving a backup key
pub fn calc_cred_id<R>(rp_id: String, rng: &mut R, backup: PubKey) -> ([u8; 81], PubKey)
where
    R: RngCore,
{
    let key_pair = generate_ephemeral_pair(rng); //key pair is (secKey, pubKey)
    let cred_key = cred_key(&key_pair.0, &backup);
    let mac_key = mac_key(&key_pair.0, &backup);
    let backup_pk = backup_pk(&cred_key, &backup);
    let cred_id = make_cred_id(key_pair.1, mac_key, rp_id);
    let backup_info = (cred_id, backup_pk);
    backup_info
}

/////////////////////////////Implementing stage 3/////////////////////////////

//checks a vector of cred_ids to find the cred_id that was created for this backup key. returns the private key associated with that cred_id
pub fn confirm_cred_ids(
    cred_id: Vec<[u8; 81]>,
    rp_id: String,
    sec_key_bytes: [u8; 32],
) -> Option<(SecKey, [u8; 81])> {
    for id in cred_id {
        if let Some(key) = confirm_cred_id(id, rp_id.clone(), sec_key_bytes) {
            return Some(key);
        }
    }
    None
}

//same as above, but takes a singular cred_id
pub fn confirm_cred_id(
    cred_id: [u8; 81],
    rp_id: String,
    sec_key_bytes: [u8; 32],
) -> Option<(SecKey, [u8; 81])> {
    let cred_key_prime;
    let sec_key = SecKey::from_bytes(&sec_key_bytes).unwrap();
    let pub_key_bytes = &cred_id[..65];
    let pub_key = PubKey::from_bytes_uncompressed(pub_key_bytes).unwrap();
    cred_key_prime = cred_key(&sec_key, &pub_key);
    let mac_key = mac_key(&sec_key, &pub_key);
    let cred_id_prime = make_cred_id(pub_key, mac_key, rp_id.clone());
    if cred_id == cred_id_prime.as_slice() {
        Some((backup_sk(cred_key_prime, sec_key_bytes), cred_id_prime))
    } else {
        None
    }
}
