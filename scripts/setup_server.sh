#!/bin/bash -e

KEYFILE=$1
IP=$2

export COMMIT="master"
export EMPTY_CEREMONY=$(cat ../e2e/empty.json)
export NGINX_CONF=$(cat server-nginx-conf)

ssh -i "$KEYFILE" -t -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null azureuser@$IP <<ENDSSH
set -e -v

sudo apt update
sudo apt install -y tmux build-essential nginx
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.36.0/install.sh | bash
export NVM_DIR="\$HOME/.nvm"
. "\$NVM_DIR/nvm.sh"
. "\$NVM_DIR/bash_completion"
nvm install node

rm -rf snark-setup-coordinator
#git clone https://github.com/celo-org/snark-setup-coordinator
cd snark-setup-coordinator/coordinator-service
git checkout $COMMIT
npm install
npm run build

echo '$EMPTY_CEREMONY' | tee ceremony/empty.json
npm run reset-db
echo COORDINATOR_CONFIG_PATH=ceremony/empty.json COORDINATOR_AUTH_TYPE=celo npm run start-nodemon > run_server.sh
chmod +x run_server.sh

echo '$NGINX_CONF' | sudo tee /etc/nginx/sites-available/default
sudo service nginx restart

tmux new-session -d -s server ./run_server.sh
ENDSSH