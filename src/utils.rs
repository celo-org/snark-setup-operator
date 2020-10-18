const ADDRESS_LENGTH: usize = 20;

use std::{
    fs::{copy, remove_file, File},
    io::{Read, Write},
    path::Path,
    str::FromStr,
};

use crate::blobstore::{upload_access_key, upload_sas};
use crate::data_structs::Ceremony;
use crate::error::{UtilsError, VerifyTranscriptError};
use anyhow::Result;
use ethers::types::{Address, PrivateKey, Signature};
use hex::ToHex;
use phase1::{ContributionMode, Phase1Parameters, ProvingSystem};
use reqwest::header::AUTHORIZATION;
use serde::Serialize;
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

pub fn verify_signed_data<T: Serialize>(data: &T, signature: &str, id: &str) -> Result<()> {
    let vrs_signature = &signature[2..];
    let rsv_signature = vrs_to_rsv(vrs_signature);
    let signature = Signature::from_str(&rsv_signature)?;
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
    private_key: &PrivateKey,
    method: &str,
    path: &str,
) -> Result<String> {
    let address = Address::from(private_key).encode_hex::<String>();
    let message = format!("{} {}", method.to_lowercase(), path.to_lowercase());
    let signature = private_key.sign(message).to_string();
    let authorization = format!("Celo 0x{}:0x{}", address, signature);
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

pub fn sign_json(private_key: &PrivateKey, value: &serde_json::Value) -> Result<String> {
    let message = serde_json::to_string(value)?;
    let signature = private_key.sign(message).to_string();
    Ok(format!("0x{}", signature))
}

pub fn address_to_string(address: &Address) -> String {
    format!("0x{}", address.encode_hex::<String>())
}

#[derive(Debug, Clone)]
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

#[derive(Debug, PartialEq, Clone)]
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
