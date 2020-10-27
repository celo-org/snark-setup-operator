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
  

## Testing

Generate keys for verifier and contributor:
```
cargo run --release --bin generate -- -f plumo-verifier.keys
cargo run --release --bin generate -- -f plumo-contributor.keys
```

Sample test file:
```
{
    "version": 0,
    "maxLocks": 3,
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
RUST_LOG=info cargo run --bin new_ceremony --release -- --upload-mode direct --chunk-size 10 --powers 12 --server-url http://localhost:8080 --verifier 0xa57b76916f19078e3f0c6f37d2a9d4ac9d14a1e2 --output-dir ~/snark-setup-coordinator/coordinator-service/.storage
```

Add the test participant and verifier:
```
RUST_LOG=info cargo run --bin control --release -- --keys-path plumo-verifier.keys add-participant --participant-id $(cat plumo-contributor.keys | jq .address -r)
RUST_LOG=info cargo run --bin control --release -- --keys-path plumo-verifier.keys add-verifier --participant-id $(cat plumo-verifier.keys | jq .address -r)
```

Contribute:
```
RUST_LOG=info cargo run --bin contribute --release -- --keys-path plumo-contributor.keys
```

Verify contribution:
```
RUST_LOG=info cargo run --bin contribute --release -- --participation-mode verify --keys-path plumo-verifier.keys
```
