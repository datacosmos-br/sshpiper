#!/bin/bash

# perm check
if [ `id -u` -ne 0 ]
  then echo Please run this script as root or sudo
  exit 1
fi

echo "starting install of SSH proxy"
# create sshpiper account
sudo useradd sshpiper
sudo usermod -L sshpiper
sudo mkdir /home/sshpiper
sudo chown sshpiper:sshpiper /home/sshpiper
# install files
ARCH=$(dpkg --print-architecture)
if [ "$ARCH" = "amd64" ]; then
    sudo wget https://github.com/TensorOpera-Inc/sshproxy/releases/download/v1.3.1/sshpiper_x86_64.tar.gz -O /home/sshpiper/download.tar.gz
elif [ "$ARCH" = "arm64" ]; then
    sudo wget https://github.com/TensorOpera-Inc/sshproxy/releases/download/v1.3.1/sshpiper_aarch64.tar.gz -O /home/sshpiper/download.tar.gz
else
    echo "Unsupported architecture: $ARCH, skipping installation of SSH proxy"
    exit 1
fi
sudo tar -xvzf /home/sshpiper/download.tar.gz -C /home/sshpiper
# reorganize files here or something
sudo curl https://raw.githubusercontent.com/TensorOpera-Inc/sshproxy/master/setup/initial.yaml -o /home/sshpiper/config.yaml
sudo ssh-keygen -t ed25519 -N "" -f /home/sshpiper/sshpiper_ed25519 -C "TensorOpera_Agent"
sudo mkdir /home/sshpiper/keys
sudo chown -R sshpiper:sshpiper /home/sshpiper/*
sudo chmod 500 /home/sshpiper/sshpiperd /home/sshpiper/yaml
sudo chmod 600 /home/sshpiper/config.yaml
sudo chmod 700 /home/sshpiper/keys
sudo chmod 400 /home/sshpiper/sshpiper_ed25519
sudo chmod 404 /home/sshpiper/sshpiper_ed25519.pub
# install service
sudo curl https://raw.githubusercontent.com/TensorOpera-Inc/sshproxy/master/setup/sshpiper_example.service -o /home/sshpiper/sshpiper.service
sudo mv /home/sshpiper/sshpiper.service /etc/systemd/system/sshpiper.service
sudo systemctl enable sshpiper
sudo systemctl start sshpiper
# remove temporary files
sudo rm /home/sshpiper/download.tar.gz
# block internal address access
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
sudo apt-get install -y iptables-persistent
sudo iptables -A INPUT -p tcp --dport 2222 -m iprange --src-range 172.16.0.0-172.31.255.255 -j REJECT
sudo iptables -A INPUT -p tcp --dport 2222 -m iprange --src-range 10.0.0.0-10.255.255.255 -j REJECT
sudo iptables -A INPUT -p tcp --dport 2222 -m iprange --src-range 192.168.0.0-192.168.255.255 -j REJECT
sudo iptables -I INPUT -p tcp --dport 2222 -i lo -j REJECT
sudo iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
sudo systemctl is-active --quiet netfilter-persistent || sudo systemctl start netfilter-persistent
sudo netfilter-persistent save

echo "SSH proxy installed"
exit 0

# the resultant filesystem should look like this:
# /home/sshpiper
# ├── config.yaml
# ├── sshpiper_ed25519
# ├── sshpiper_ed25519.pub
# ├── sshpiper
# ├── yaml
# └── keys
# /etc/systemd/system/sshpiper.service
