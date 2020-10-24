#!/bin/bash -e

KEYFILE=$1
IP=$2

export COMMIT="master"
export EMPTY_CEREMONY=$(cat ../e2e/empty.json)
export NGINX_CONF=$(cat server-nginx-conf)
export STORAGE_KEY=$(cat storage_access_key)

echo Setting up server

ssh -i "$KEYFILE" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null azureuser@$IP <<ENDSSH
set -e -v

sudo apt update
sudo apt install -y tmux build-essential nginx
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.36.0/install.sh | bash
export NVM_DIR="\$HOME/.nvm"
. "\$NVM_DIR/nvm.sh"
. "\$NVM_DIR/bash_completion"
nvm install node

rm -rf snark-setup-coordinator
git clone https://github.com/celo-org/snark-setup-coordinator
cd snark-setup-coordinator/coordinator-service
git checkout $COMMIT
npm install
npm run build

echo '$EMPTY_CEREMONY' | tee ceremony/empty.json
npm run reset-db
echo "$STORAGE_KEY" | tee storage-key
echo COORDINATOR_CONFIG_PATH=ceremony/empty.json COORDINATOR_AUTH_TYPE=celo COORDINATOR_AZURE_ACCESS_KEY_FILE=./storage-key COORDINATOR_CHUNK_STORAGE_TYPE=azure COORDINATOR_AZURE_STORAGE_ACCOUNT=optimisticstorage COORDINATOR_AZURE_CONTAINER=chunks npm run start-nodemon > run_server.sh
chmod +x run_server.sh

echo '$NGINX_CONF' | sudo tee /etc/nginx/sites-available/default
sudo service nginx restart

tmux kill-server || true
tmux new-session -d -s server ./run_server.sh
set +e
exit 0
ENDSSH

echo Set up server

exit 0