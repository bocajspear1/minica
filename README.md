# MiniCA

MiniCA is a LAB-ONLY (Don't use this in production systems or untrusted networks!) CA made for use with my other project FakerNet. It has simple web interface than can be easily scripted with Python for curl. POST a CSR `csrfile` and the CA private key password `password` (for some form of authentication) you get a signed certificate.

Password is auto-generated an in the `./certs/ca.pass` file. Keep this safe.

Example:
```
curl --cacert ./certs/ca.crt -F csrfile=@server.csr -F password=<PASSWORD> https://localhost:8443
```

The CA cert is available at `/static/certs/fakernet-ca.crt` or `/static/certs/fakernet-ca.p7b` on the web server.

Certs are stored in the `./certs/` directory.