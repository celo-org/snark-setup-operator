#!/bin/bash -e

ps auwx | grep "./bin/nodemon" | grep -v grep | awk '{print $2}' | xargs kill || true

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
COORDINATOR_CONFIG_PATH=ceremony/empty.json COORDINATOR_AUTH_TYPE=celo npm run start-nodemon &
sleep 5
popd

echo 1 | RUST_LOG=info cargo run --bin new_ceremony --release -- --upload-mode direct --chunk-size 10 --powers 12 --server-url http://localhost:8080  --verifier 0xb522a4df212f0baa380d1dd480affbb955b39595 --participant 0xad0e687cda8fe660895068e72cd2d8117a1601b5 --output-dir ./snark-setup-coordinator/coordinator-service/.storage --unsafe-passphrase --keys-path $BASE_DIR/plumo-verifier.keys
echo 1 | RUST_LOG=info cargo run --release  --bin contribute -- --unsafe-passphrase --exit-when-finished-contributing --keys-path $BASE_DIR/plumo-contributor.keys
echo 1 | RUST_LOG=info cargo run --release  --bin contribute -- --unsafe-passphrase --exit-when-finished-contributing --keys-path $BASE_DIR/plumo-verifier.keys --participation-mode verify
curl http://localhost:8080/ceremony > transcript.json
RUST_LOG=info cargo run --release --bin verify_transcript -- --beacon-hash 0000000000000000000000000000000000000000000000000000000000000000
