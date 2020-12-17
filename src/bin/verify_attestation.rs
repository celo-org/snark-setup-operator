use ethers::types::{Address, Signature};
use gumdrop::Options;
use snark_setup_operator::utils::{extract_signature_from_attestation, ADDRESS_LENGTH};
use std::io::Read;
use std::str::FromStr;

#[derive(Debug, Options, Clone)]
pub struct VerifyAttestationOpts {
    help: bool,
    #[options(
        help = "the path of the output keys file",
        default = "plumo.attestation"
    )]
    pub attestation_path: String,
    #[options(help = "the expected address", required)]
    pub expected_address: String,
}

fn main() {
    let opts: VerifyAttestationOpts = VerifyAttestationOpts::parse_args_default_or_exit();
    let mut file =
        std::fs::File::open(&opts.attestation_path).expect("Should have opened attestation file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Should have read attestation");
    let (message, address_hex, signature) = extract_signature_from_attestation(&contents)
        .expect("Should have extracted signature from attestation");
    println!("Verifying message \"{}\" with address \"{}\" and signature \"{}\"", message, address_hex, signature);
    let address_bytes = hex::decode(&address_hex[2..]).expect("Could not decode address");
    let mut address = [0u8; ADDRESS_LENGTH];
    address.copy_from_slice(&address_bytes);
    let address = Address::from(address);
    let signature = Signature::from_str(&signature).expect("Should have parsed signature");
    match signature.verify(message, address) {
        Ok(_) => {}
        Err(e) => {
            panic!("Could not verify signature: {}", e.to_string());
        }
    }
    if address_hex != opts.expected_address {
        panic!(
            "Addresses were different. Expected {}, got {}",
            opts.expected_address, address
        );
    }
    println!("Attestation verified successfully!");
}
