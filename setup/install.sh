#!/bin/bash

echo "starting install of SSH proxy"
# create sshpiper account
sudo useradd sshpiper
sudo usermod -L sshpiper
sudo mkdir /home/sshpiper
sudo chown sshpiper:sshpiper /home/sshpiper
# install files
ARCH=$(dpkg --print-architecture)
if [ "$ARCH" = "amd64" ]; then
    sudo curl https://github.com/TensorOpera-Inc/sshproxy/releases/download/v1.3.0/sshpiper_x86_64.tar.gz -o /home/sshpiper/download.tar.gz
elif [ "$ARCH" = "arm64" ]; then
        sudo curl https://github.com/TensorOpera-Inc/sshproxy/releases/download/v1.3.0/sshpiper_aarch64.tar.gz -o /home/sshpiper/download.tar.gz
else
    echo "Unsupported architecture: $ARCH, skipping installation of SSH proxy"
    return
fi
sudo tar -xvzf /home/sshpiper/download.tar.gz
# reorganize files here or something
sudo curl https://raw.githubusercontent.com/TensorOpera-Inc/sshproxy/master/setup/initial.yaml -o /home/sshpiper/config.yaml
sudo ssh-keygen -t ed25519 -N "" -f /home/sshpiper/sshpiper_ed25519
sudo chown -R sshpiper:sshpiper /home/sshpiper/*
sudo chmod -R 500 /home/sshpiper/sshpiperd /home/sshpiper/plugins
sudo chmod 600 /home/sshpiper/config.yaml
sudo chmod 400 /home/sshpiper/sshpiper_ed25519
sudo chmod 404 /home/sshpiper/sshpiper_ed25519.pub
# install service
sudo curl https://raw.githubusercontent.com/TensorOpera-Inc/sshproxy/master/setup/sshpiper_example.service -o /home/sshpiper/sshpiper.service
sudo mv /home/sshpiper/sshpiper.service /etc/systemd/system/sshpiper.service
sudo systemctl enable sshpiper
sudo systemctl start sshpiper
# remove temporary files
sudo rm /home/sshpiper/download.tar.gz

echo "SSH proxy installed"

# the resultant filesystem should look like this:
# /home/sshpiper
# ├── config.yaml
# ├── sshpiper_ed25519
# ├── sshpiper_ed25519.pub
# ├── sshpiper
# └── yaml
# /etc/systemd/system/sshpiper.service
