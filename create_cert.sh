openssl req -x509 -newkey rsa:4096 -keyout /tmp/tls_key.pem -out /tmp/tls_cert.pem -nodes -days 365 -subj "/CN=localhost"
