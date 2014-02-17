$ openssl genrsa -out private-key.pem 2056
$ openssl req -new -key private-key.pem -out csr.pem
$ openssl x509 -req -in csr.pem -signkey private-key.pem -out cert.pem
