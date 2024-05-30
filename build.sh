#!/bin/bash
mkdir out
mkdir out/arm64
GOOS=linux GOARCH=arm64 go build -tags full -o out/arm64 ./...
mkdir out/amd64
GOOS=linux GOARCH=amd64 go build -tags full -o out/amd64 ./...

cd out/arm64 
tar -czvf sshpiper_aarch64.tar.gz sshpiperd yaml
cd ../amd64
tar -czvf sshpiper_x86_64.tar.gz sshpiperd yaml
cd ..
mv arm64/sshpiper_aarch64.tar.gz ../
mv amd64/sshpiper_x86_64.tar.gz ../
cd .. && rm -r out
echo "build complete"
