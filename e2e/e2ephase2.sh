#!/bin/bash -e

ps auwx | grep "nodemon" | grep -v grep | awk '{print $2}' | xargs kill || true

COMMIT="master"
BASE_DIR=$(pwd)

rm -rf snark-setup-coordinator
git clone https://github.com/celo-org/snark-setup-coordinator
pushd snark-setup-coordinator/coordinator-service
git checkout $COMMIT
npm install
npm run build

cp $BASE_DIR/empty.json ceremony
npm run reset-db
JSON_LOGGING=true COORDINATOR_CONFIG_PATH=ceremony/empty.json COORDINATOR_AUTH_TYPE=celo npm run start-nodemon &
sleep 5
popd

rm -f transcript

echo 1 | RUST_LOG=error cargo run --bin new_ceremony --release -- --phase phase2 --upload-mode direct --chunk-size 1024 --powers 18 --num-epochs 1 --num-validators 1 --phase1-filename phase2_init --server-url http://localhost:8080  --verifier 0xb522a4df212f0baa380d1dd480affbb955b39595 --participant 0xc31130dc73f078f99fac28e250535cbc3407608d --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-file $BASE_DIR/plumo-verifier.keys --deployer 0xb522a4df212f0baa380d1dd480affbb955b39595
echo 1 | RUST_LOG=info cargo run --release  --bin contribute -- --phase phase2 --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/plumo-contributor.keys --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release  --bin contribute -- --phase phase2 --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/plumo-verifier.keys --participation-mode verify --coordinator-url http://localhost:8080
#echo 1 | RUST_LOG=info cargo run --release  --bin control -- --phase phase2 -i new_challenge.query -I new_challenge.full --unsafe-passphrase --keys-file $BASE_DIR/plumo-verifier.keys  --coordinator-url http://localhost:8080 apply-beacon --beacon-hash 0000000000000000000000000000000000000000000000000000000000000000 --verify-transcript --expected-participant 0xc31130dc73f078f99fac28e250535cbc3407608d
echo 1 | RUST_LOG=info cargo run --release  --bin control -- --phase phase2 -i new_challenge.query -I new_challenge.full --unsafe-passphrase --keys-file $BASE_DIR/plumo-verifier.keys --coordinator-url http://localhost:8080 new-round --verify-transcript --expected-participant 0xc31130dc73f078f99fac28e250535cbc3407608d --new-participant 0x31e598a18069f75983dc00c39aafc7e9f7b71aee --publish --shutdown-delay-time-in-secs 10

echo 1 | RUST_LOG=info cargo run --release  --bin contribute -- --phase phase2 --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/plumo-contributor-2.keys --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release  --bin contribute -- --phase phase2 --unsafe-passphrase --exit-when-finished-contributing --keys-file $BASE_DIR/plumo-verifier.keys --participation-mode verify --coordinator-url http://localhost:8080
echo 1 | RUST_LOG=info cargo run --release  --bin control -- --phase phase2 -i new_challenge.query -I new_challenge.full --unsafe-passphrase --keys-file $BASE_DIR/plumo-verifier.keys  --coordinator-url http://localhost:8080 apply-beacon --beacon-hash 0000000000000000000000000000000000000000000000000000000000000000 --verify-transcript --expected-participant 0x31e598a18069f75983dc00c39aafc7e9f7b71aee
RUST_LOG=info cargo run --release --bin verify_transcript -- --phase phase2 --num-epochs 1 --num-validators 1 --phase1-filename phase2_init --phase1-powers 18 --beacon-hash 0000000000000000000000000000000000000000000000000000000000000000 --chunk-size 1024 -i new_challenge.query -I new_challenge.full

