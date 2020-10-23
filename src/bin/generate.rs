use age::cli_common::read_secret;
use age::{
    armor::{ArmoredWriter, Format},
    cli_common::Passphrase,
    EncryptError, Encryptor,
};
use anyhow::Result;
use blake2::{Blake2s, Digest};
use ethers::signers::LocalWallet;
use gumdrop::Options;
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretVec};
use snark_setup_operator::data_structs::PlumoSetupKeys;
use snark_setup_operator::utils::address_to_string;
use std::io::Write;

const PLUMO_SETUP_PERSONALIZATION: &[u8] = b"PLUMOSET";

#[derive(Debug, Options, Clone)]
pub struct GenerateOpts {
    help: bool,
    #[options(help = "the path of the output keys file", default = "plumo.keys")]
    pub file_path: String,
}

fn encrypt(encryptor: Encryptor, secret: &[u8]) -> Result<String> {
    let mut encrypted_output = vec![];
    let mut writer = encryptor
        .wrap_output(ArmoredWriter::wrap_output(
            &mut encrypted_output,
            Format::Binary,
        )?)
        .map_err(|e| match e {
            EncryptError::Io(e) => e,
        })?;
    std::io::copy(&mut std::io::Cursor::new(secret), &mut writer)?;
    writer.finish()?;
    let encrypted_secret = hex::encode(&encrypted_output);
    Ok(encrypted_secret.to_string())
}

fn main() {
    let opts: GenerateOpts = GenerateOpts::parse_args_default_or_exit();
    let entropy = read_secret("Enter some entropy for your Plumo seed", "Entropy", None)
        .expect("Should have read entropy");

    let mut file = std::fs::File::create(&opts.file_path).expect("Should have created keys file");
    let (plumo_encryptor, private_key_encryptor) =
        match age::cli_common::read_or_generate_passphrase() {
            Ok(Passphrase::Typed(passphrase)) => (
                age::Encryptor::with_user_passphrase(passphrase.clone()),
                age::Encryptor::with_user_passphrase(passphrase),
            ),
            Ok(Passphrase::Generated(new_passphrase)) => {
                println!(
                    "Generated new passphrase: {}",
                    new_passphrase.expose_secret()
                );
                (
                    age::Encryptor::with_user_passphrase(new_passphrase.clone()),
                    age::Encryptor::with_user_passphrase(new_passphrase),
                )
            }
            Err(_) => panic!("Should have read or generated passphrase"),
        };

    let mut rng = OsRng;
    let mut plumo_seed = vec![0u8; 64];
    rng.fill_bytes(&mut plumo_seed[..]);

    let plumo_seed = SecretVec::new(plumo_seed);
    let mut hasher = Blake2s::with_params(&[], &[], PLUMO_SETUP_PERSONALIZATION);
    hasher.update(entropy.expose_secret().as_bytes());
    hasher.update(plumo_seed.expose_secret());

    let private_key = LocalWallet::new(&mut rng);
    let address = address_to_string(&private_key.address());
    let private_key = private_key.signer().to_bytes();

    let encrypted_plumo_seed = encrypt(plumo_encryptor, hasher.finalize().as_slice())
        .expect("Should have encrypted Plumo seed");
    let encrypted_plumo_private_key = encrypt(private_key_encryptor, &private_key[..])
        .expect("Should have encrypted private key");

    let plumo_setup_keys = PlumoSetupKeys {
        encrypted_seed: encrypted_plumo_seed.to_string(),
        encrypted_private_key: encrypted_plumo_private_key.to_string(),
        address,
    };
    file.write_all(
        &serde_json::to_vec(&plumo_setup_keys).expect("Should have converted setup keys to vector"),
    )
    .expect("Should have written setup keys successfully to file");
    println!("Done! Your keys are ready in {}.", &opts.file_path);
}
