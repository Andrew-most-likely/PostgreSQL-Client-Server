#!/bin/bash
# Auto-generate SSL certificates inside the container on build up twin

SSL_DIR="/var/lib/postgresql/ssl"

if [ ! -f "$SSL_DIR/server.key" ]; then
    echo "Generating SSL certificates..."
    
    mkdir -p "$SSL_DIR"
    
    openssl genrsa -out "$SSL_DIR/server.key" 2048
    
    openssl req -new -x509 -days 365 -key "$SSL_DIR/server.key" \
        -out "$SSL_DIR/server.crt" \
        -subj "/C=US/ST=State/L=City/O=SecureBank/CN=secure-db"
    
    chown postgres:postgres "$SSL_DIR/server.key" "$SSL_DIR/server.crt"
    chmod 600 "$SSL_DIR/server.key"
    chmod 644 "$SSL_DIR/server.crt"
    
    echo "SSL certificates generated"
else
    echo "SSL certificates already exist"
fi