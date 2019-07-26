# MiniCA

MiniCA is a LAB-ONLY (Don't use this in production systems or untrusted networks!) CA made for use with my other project FakerNet. It has simple web interface than can be easily scripted with Python for curl. POST a CSR `csrfile` and the CA private key password `password` (for some form of authentication) you get a signed certificate.

Password is auto-generated an in the `./certs/ca.pass` file. Keep this safe.

Example:
```
curl --cacert ./certs/ca.crt -F csrfile=@server.csr -F password=<PASSWORD> https://localhost:8443
```

The CA cert is available at `/static/certs/fakernet-ca.crt` or `/static/certs/fakernet-ca.p7b` on the web server.

Certs are stored in the `./certs/` directory.

### Sources

Thanks to these pages for help:
#### Go PKI and Certificates
* [Create a PKI in GoLang](https://fale.io/blog/2017/06/05/create-a-pki-in-golang/)
* [How to use an encrypted private key with golang ssh  - StackOverflow](https://stackoverflow.com/questions/42105432/how-to-use-an-encrypted-private-key-with-golang-ssh)
* [Golang RSA encrypt and decrypt example ](https://gist.github.com/miguelmota/3ea9286bd1d3c2a985b67cac4ba2130a)
* [Using encrypted private keys with Golang HTTPS server](https://medium.com/@prateeknischal25/using-encrypted-private-keys-with-golang-server-379919955854)
* [How create rsa private key with passphrase in golang  - StackOverflow](https://stackoverflow.com/questions/37316370/how-create-rsa-private-key-with-passphrase-in-golang)
* [Signing certificate request with certificate authority  - StackOverflow](https://stackoverflow.com/questions/42643048/signing-certificate-request-with-certificate-authority)
* [Go: How do I add an extension (subjectAltName) to a x509.Certificate?  - StackOverflow](https://stackoverflow.com/questions/26441547/go-how-do-i-add-an-extension-subjectaltname-to-a-x509-certificate)
#### OpenSSL Commands
* [Verify a certificate chain using openssl verify - StackOverflow](https://stackoverflow.com/questions/25482199/verify-a-certificate-chain-using-openssl-verify)
* [The Most Common OpenSSL Commands](https://www.sslshopper.com/article-most-common-openssl-commands.html)
* [How to convert a certificate into the appropriate format](https://knowledge.digicert.com/solution/SO26630.html)