use age::cli_common::read_secret;
use age::cli_common::Passphrase;
use blake2::{Blake2s, Digest};
use ethers::signers::{LocalWallet, Signer};
use futures::executor::block_on;
use gumdrop::Options;
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use snark_setup_operator::data_structs::{Attestation, PlumoSetupKeys};
use snark_setup_operator::utils::{
    address_to_string, encrypt, trim_newline, PLUMO_SETUP_PERSONALIZATION,
};
use std::io::{self, Write};

#[derive(Debug, Options, Clone)]
pub struct GenerateOpts {
    help: bool,
    #[options(help = "the path of the output keys file", default = "plumo.keys")]
    pub keys_path: String,
    #[options(help = "read passphrase from stdin. THIS IS UNSAFE as it doesn't use pinentry!")]
    pub unsafe_passphrase: bool,
}

fn main() {
    let opts: GenerateOpts = GenerateOpts::parse_args_default_or_exit();
    let mut file = std::fs::File::create(&opts.keys_path).expect("Should have created keys file");
    let (entropy, attestation_message, plumo_encryptor, private_key_encryptor) = if !opts
        .unsafe_passphrase
    {
        let mut attestation_message = String::new();
        loop {
            println!(
                "Enter some identifying information, such as your Twitter, GitHub or Keybase handle (up to 106 characters):"
            );
            io::stdin()
                .read_line(&mut attestation_message)
                .expect("Should have read attestation message");
            trim_newline(&mut attestation_message);
            if attestation_message.len() > 0 {
                break;
            } else {
                println!("Can't be empty!");
            }
        }

        let entropy = read_secret("Enter some entropy for your Plumo seed", "Entropy", None)
            .expect("Should have read entropy");

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
        (
            entropy,
            attestation_message,
            plumo_encryptor,
            private_key_encryptor,
        )
    } else {
        println!("Enter passphrase:");
        let passphrase =
            SecretString::new(rpassword::read_password().expect("Should have read passphrase"));
        (
            SecretString::new(String::new()),
            String::new(),
            age::Encryptor::with_user_passphrase(passphrase.clone()),
            age::Encryptor::with_user_passphrase(passphrase.clone()),
        )
    };

    let mut rng = OsRng;
    let mut plumo_seed = vec![0u8; 64];
    rng.fill_bytes(&mut plumo_seed[..]);

    let plumo_seed = SecretVec::new(plumo_seed);
    let mut hasher = Blake2s::with_params(&[], &[], PLUMO_SETUP_PERSONALIZATION);
    hasher.update(entropy.expose_secret().as_bytes());
    hasher.update(plumo_seed.expose_secret());

    let private_key = LocalWallet::new(&mut rng);
    let attestation_signature = block_on(private_key.sign_message(&attestation_message))
        .expect("Should have signed attestation");
    let address = address_to_string(&private_key.address());
    let private_key = private_key.signer().to_bytes();

    let encrypted_plumo_seed = encrypt(plumo_encryptor, hasher.finalize().as_slice())
        .expect("Should have encrypted Plumo seed");
    let encrypted_plumo_private_key = encrypt(private_key_encryptor, &private_key[..])
        .expect("Should have encrypted private key");

    let plumo_setup_keys = PlumoSetupKeys {
        encrypted_seed: encrypted_plumo_seed.to_string(),
        encrypted_private_key: encrypted_plumo_private_key.to_string(),
        encrypted_extra_entropy: None,
        attestation: Attestation {
            id: attestation_message,
            address: address.clone(),
            signature: attestation_signature.to_string(),
        },
        address,
    };
    file.write_all(
        &serde_json::to_vec(&plumo_setup_keys).expect("Should have converted setup keys to vector"),
    )
    .expect("Should have written setup keys successfully to file");
    file.sync_all().expect("Should have synced to disk");
    println!(
        "Done! Your keys are ready in {}. Your address is : {}",
        &opts.keys_path, plumo_setup_keys.address
    );
}
