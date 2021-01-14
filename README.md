# SNARK setup operator

The operator is responsible for monitoring and verifying the operation of the coordinator.

Tools included:
* `contribute` - run a contributor or a verifier.

* `monitor` - checks the status of the setup:
  * Did any participants time out?
  * Did all chunks finish?
  * What are the incomplete chunks?
  
* `verify_transcript` - given a coordinator state and participant IDs, verifies the entire setup as run by the coordinator:
  * Verify each contribution in each chunks, including signatures and the hash chain.
  * Combine and apply the beacon.
  * Verify ratios hold.
  
* `control` - perform ceremony update operations:
  * `add-participant` - add a contributor.
  * `add-verifier` - add a verifier.
  * `remove-participant` - remove a contributor, release the locks they hold and delete contributions they were part of and their descendants.
  * `remove-verifier` - remove a verifier and release the locks they hold.
  
* `new_ceremony` - initialize a ceremony.
  
## Compilation

### Native

On Linux and macOS, building directly with `cargo build --release` should work, as long as you have the usual build toolchain installed (e.g. `build-essential` on Ubuntu). To build without ADX and BMI2 support, use `cargo build --release --no-default-features`.

On Windows, you have to use the GNU toolchain to compile and have the following in your PATH:
* `gcc` - which can be downloaded from http://mingw-w64.org/doku.php.
* `perl` - the version from https://www.msys2.org/.

### Cross compilation

Use the `cross-compile.sh` script in `scripts`, with one of `linux, windows, macos, macos-m1`. This will create an `out` folder in `build` with the binaries for that OS.

For example, to build for windows, you run `./scripts/cross-compile.sh windows` and you'll find `contribute-windows.exe`, `generate-windows.exe`, `contribute-windows-noasm.exe` and `generate-windows-noasm.exe` in `./build/out`.

The `no-asm` binaries will run on CPUs without ADX and BMI2 support, which has been introduced around 2015.

## Testing

Generate keys for verifier and contributor:
```
cargo run --release --bin generate -- -k plumo-verifier.keys
cargo run --release --bin generate -- -k plumo-contributor.keys
```

Sample test file:
```
{
    "version": 0,
    "maxLocks": 3,
    "round": 0,
    "shutdownSignal": false,
    "contributorIds": [
    ],
    "verifierIds": [
        "address from plumo-verifier.keys"
    ],
    "chunks": [
    ]
}
```

Contents of .env:
```
COORDINATOR_CONFIG_PATH=ceremony/test.json
COORDINATOR_AUTH_TYPE=celo
```

Initializing ceremony:
```
RUST_LOG=info cargo run --bin new_ceremony --release -- --upload-mode direct --chunk-size 10 --powers 12 --server-url http://localhost:8080 --verifier $(cat plumo-verifier.keys | jq .address -r) --deployer $(cat plumo-verifier.keys | jq .address -r) --output-dir ~/snark-setup-coordinator/coordinator-service/.storage -k plumo-verifier.keys
```

Add the test participant and verifier:
```
RUST_LOG=info cargo run --bin control --release -- --keys-file plumo-verifier.keys add-participant --participant-id $(cat plumo-contributor.keys | jq .address -r)
RUST_LOG=info cargo run --bin control --release -- --keys-file plumo-verifier.keys add-verifier --participant-id $(cat plumo-verifier.keys | jq .address -r)
```

Contribute:
```
RUST_LOG=info cargo run --bin contribute --release -- --keys-file plumo-contributor.keys
```

Verify contribution:
```
RUST_LOG=info cargo run --bin contribute --release -- --participation-mode verify --keys-file plumo-verifier.keys
```
