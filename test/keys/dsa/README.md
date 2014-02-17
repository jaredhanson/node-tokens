$ openssl dsaparam -out dsa_params.pem 1024
$ openssl gendsa -out private-key.pem dsa_params.pem
$ openssl req -new -key private-key.pem -out csr.pem
$ openssl x509 -req -in csr.pem -signkey private-key.pem -out cert.pem
