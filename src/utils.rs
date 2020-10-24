const ADDRESS_LENGTH: usize = 20;

use std::{
    fs::{copy, remove_file, File},
    io::{Read, Write},
    path::Path,
    str::FromStr,
};

use crate::blobstore::{upload_access_key, upload_sas};
use crate::data_structs::{Ceremony, PlumoSetupKeys, ProcessorData};
use crate::error::{UtilsError, VerifyTranscriptError};
use anyhow::Result;
use ethers::types::{Address, Signature};
use hex::ToHex;
use phase1::{ContributionMode, Phase1Parameters, ProvingSystem};
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::Serialize;
use sysinfo::{ProcessorExt, System, SystemExt};
use zexe_algebra::PairingEngine;

pub fn copy_file_if_exists(file_path: &str, dest_path: &str) -> Result<()> {
    if Path::new(file_path).exists() {
        copy(file_path, dest_path)?;
    }
    Ok(())
}

pub fn download_file(url: &str, file_path: &str) -> Result<()> {
    remove_file_if_exists(file_path)?;
    let mut resp = reqwest::blocking::get(url)?.error_for_status()?;
    let mut out = File::create(file_path)?;
    resp.copy_to(&mut out)?;
    Ok(())
}

pub async fn download_file_async(url: &str, file_path: &str) -> Result<()> {
    remove_file_if_exists(file_path)?;
    let mut resp = reqwest::get(url).await?.error_for_status()?;
    let mut out = File::create(file_path)?;
    while let Some(chunk) = resp.chunk().await? {
        out.write(&chunk)?;
    }
    Ok(())
}

pub async fn upload_file_to_azure_async(file_path: &str, url: &str) -> Result<()> {
    upload_sas(file_path, url).await?;
    Ok(())
}

pub async fn upload_file_to_azure_with_access_key_async(
    file_path: &str,
    access_key: &str,
    account: &str,
    container: &str,
    path: &str,
) -> Result<()> {
    upload_access_key(file_path, access_key, account, container, path).await?;
    Ok(())
}

pub async fn upload_file_direct_async(
    authorization: &str,
    file_path: &str,
    url: &str,
) -> Result<()> {
    let mut file = File::open(file_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    let client = reqwest::Client::new();
    client
        .post(url)
        .header(AUTHORIZATION, authorization)
        .header(CONTENT_TYPE, "application/octet-stream")
        .body(contents)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

pub fn vrs_to_rsv(rsv: &str) -> String {
    format!("{}{}{}", &rsv[2..66], &rsv[66..130], &rsv[..2])
}

pub fn remove_file_if_exists(file_path: &str) -> Result<()> {
    if Path::new(file_path).exists() {
        remove_file(file_path)?;
    }
    Ok(())
}

use ethers::signers::{LocalWallet, Signer};

pub fn verify_signed_data<T: Serialize>(data: &T, signature: &str, id: &str) -> Result<()> {
    let signature = Signature::from_str(&signature[2..])?;
    let serialized_data = serde_json::to_string(data)?;

    let deserialized_id = hex::decode(&id[2..])?;
    if deserialized_id.len() != ADDRESS_LENGTH {
        return Err(VerifyTranscriptError::IDWrongLength(deserialized_id.len()).into());
    }
    let mut address = [0u8; ADDRESS_LENGTH];
    address.copy_from_slice(&deserialized_id);
    let address = Address::from(address);
    signature.verify(serialized_data, address)?;

    Ok(())
}

pub fn read_hash_from_file(file_name: &str) -> Result<String> {
    let mut hash = vec![];
    File::open(file_name)
        .expect("Should have opened hash file.")
        .read_to_end(&mut hash)
        .expect("Should have read hash file.");
    let hash_hex = hex::encode(&hash);
    Ok(hash_hex)
}

pub fn proving_system_from_str(proving_system_str: &str) -> Result<ProvingSystem> {
    let proving_system = match proving_system_str {
        "groth16" => ProvingSystem::Groth16,
        "marlin" => ProvingSystem::Marlin,
        _ => {
            return Err(VerifyTranscriptError::UnsupportedProvingSystemError(
                proving_system_str.to_string(),
            )
            .into());
        }
    };
    Ok(proving_system)
}

pub fn check_challenge_hashes_same(a: &str, b: &str) -> Result<()> {
    if a != b {
        return Err(VerifyTranscriptError::WrongChallengeHash(a.to_string(), b.to_string()).into());
    }

    Ok(())
}

pub fn check_response_hashes_same(a: &str, b: &str) -> Result<()> {
    if a != b {
        return Err(VerifyTranscriptError::WrongResponseHash(a.to_string(), b.to_string()).into());
    }

    Ok(())
}

pub fn check_new_challenge_hashes_same(a: &str, b: &str) -> Result<()> {
    if a != b {
        return Err(
            VerifyTranscriptError::WrongNewChallengeHash(a.to_string(), b.to_string()).into(),
        );
    }

    Ok(())
}

pub fn get_authorization_value(
    private_key: &LocalWallet,
    method: &str,
    path: &str,
) -> Result<String> {
    let address = private_key.address().encode_hex::<String>();
    let message = format!("{} {}", method.to_lowercase(), path.to_lowercase());
    let signature: Signature = futures::executor::block_on(private_key.sign_message(message))?;
    let authorization = format!("Celo 0x{}:0x{}", address, signature.to_string());
    Ok(authorization)
}

pub fn create_parameters_for_chunk<E: PairingEngine>(
    ceremony: &Ceremony,
    chunk_index: usize,
) -> Result<Phase1Parameters<E>> {
    let proving_system = proving_system_from_str(ceremony.parameters.proving_system.as_str())?;
    let parameters = Phase1Parameters::<E>::new_chunk(
        ContributionMode::Chunked,
        chunk_index,
        ceremony.parameters.chunk_size,
        proving_system,
        ceremony.parameters.power,
        ceremony.parameters.batch_size,
    );
    Ok(parameters)
}

pub fn create_full_parameters<E: PairingEngine>(
    ceremony: &Ceremony,
) -> Result<Phase1Parameters<E>> {
    let proving_system = proving_system_from_str(ceremony.parameters.proving_system.as_str())?;
    let parameters = Phase1Parameters::<E>::new_full(
        proving_system,
        ceremony.parameters.power,
        ceremony.parameters.batch_size,
    );
    Ok(parameters)
}

pub fn sign_json(private_key: &LocalWallet, value: &serde_json::Value) -> Result<String> {
    let message = serde_json::to_string(value)?;
    let signature: Signature = futures::executor::block_on(private_key.sign_message(message))?;
    Ok(format!("0x{}", signature.to_string()))
}

pub fn address_to_string(address: &Address) -> String {
    format!("0x{}", address.encode_hex::<String>())
}

#[derive(Debug, Clone, Copy)]
pub enum UploadMode {
    Auto,
    Azure,
    Direct,
}

pub fn upload_mode_from_str(upload_mode: &str) -> Result<UploadMode> {
    match upload_mode {
        "auto" => Ok(UploadMode::Auto),
        "azure" => Ok(UploadMode::Azure),
        "direct" => Ok(UploadMode::Direct),
        _ => Err(UtilsError::UnknownUploadModeError(upload_mode.to_string()).into()),
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ParticipationMode {
    Contribute,
    Verify,
}

pub fn participation_mode_from_str(participation_mode: &str) -> Result<ParticipationMode> {
    match participation_mode {
        "contribute" => Ok(ParticipationMode::Contribute),
        "verify" => Ok(ParticipationMode::Verify),
        _ => Err(UtilsError::UnknownParticipationModeError(participation_mode.to_string()).into()),
    }
}

fn decrypt(passphrase: &SecretString, encrypted: &str) -> Result<Vec<u8>> {
    let decoded = SecretVec::new(hex::decode(encrypted)?);
    let decryptor = age::Decryptor::new(decoded.expose_secret().as_slice())?;
    let mut output = vec![];
    if let age::Decryptor::Passphrase(decryptor) = decryptor {
        let mut reader = decryptor.decrypt(passphrase, None)?;
        reader.read_to_end(&mut output)?;
    } else {
        return Err(UtilsError::UnsupportedDecryptorError.into());
    }

    Ok(output)
}

pub fn read_keys(
    keys_path: &str,
    should_use_stdin: bool,
) -> Result<(SecretVec<u8>, SecretVec<u8>)> {
    let mut contents = String::new();
    std::fs::File::open(&keys_path)?.read_to_string(&mut contents)?;
    let keys: PlumoSetupKeys = serde_json::from_str(&contents)?;
    let description = "Enter your Plumo setup passphrase:";
    let passphrase = if should_use_stdin {
        println!("{}", description);
        SecretString::new(rpassword::read_password()?)
    } else {
        age::cli_common::read_secret(description, "Passphrase", None)
            .map_err(|_| UtilsError::CouldNotReadPassphraseError)?
    };
    let plumo_seed = SecretVec::new(decrypt(&passphrase, &keys.encrypted_seed)?);
    let plumo_private_key = SecretVec::new(decrypt(&passphrase, &keys.encrypted_private_key)?);

    Ok((plumo_seed, plumo_private_key))
}

pub fn collect_processor_data() -> Result<Vec<ProcessorData>> {
    let s = System::new();
    let processors = s
        .get_processors()
        .iter()
        .map(|p| ProcessorData {
            name: p.get_name().to_string(),
            brand: p.get_brand().to_string(),
            frequency: p.get_frequency().to_string(),
        })
        .collect();
    Ok(processors)
}
