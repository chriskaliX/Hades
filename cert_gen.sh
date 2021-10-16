#!/bin/bash

# 拷贝忍者, 待会把笔记记录在这

rm -rf cert
mkdir cert
cd cert

CA_CONFIG="
[req]
distinguished_name=dn
[ dn ]
[ ext ]
basicConstraints=CA:TRUE,pathlen:0
"

cat << EOF > "v3.ext"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = $1
EOF

#ca 证书  /etc/ssl/openssl.cnf
openssl genrsa -out ca.key 2048
openssl req  -config <(echo "$CA_CONFIG") -new -x509 -days 36500 -subj "/C=GB/L=China/O=$2/CN=$3" -key ca.key -out ca.crt
openssl x509 -noout -text -in ca.crt>/dev/null

#server
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/C=GB/L=China/O=$2/CN=$3"  -out server.csr
openssl x509 -req -sha256 -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -in server.csr -extfile "v3.ext" -out server.crt
openssl x509 -noout -text -in server.crt>/dev/null

#agent
openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/C=GB/L=China/O=$2/CN=$3"  -out client.csr
openssl x509 -req -sha256 -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -in client.csr -extfile "v3.ext" -out client.crt
openssl x509 -noout -text -in client.crt>/dev/null

rm -rf v3.ext ca.srl client.csr server.csr

echo "generate cert ok!"

cd ../

cp cert/* server/transport/conf/
echo "update transport cert ok!"

cp cert/ca.crt cert/client.crt cert/client.key agent/transport/connection
echo "update agent cert ok!"
echo "success!"