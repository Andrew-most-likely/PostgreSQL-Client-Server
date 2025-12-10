#!/bin/bash
set -e

echo "================================================"
echo " Starting Secure PostgreSQL Container"
echo "================================================"

# This script runs BEFORE postgres initializes
# Generate SSL certificates in a temporary location first

TEMP_SSL_DIR="/tmp/ssl"
mkdir -p "$TEMP_SSL_DIR"

echo " Generating SSL certificates..."

# Generate private key
openssl genrsa -out "$TEMP_SSL_DIR/server.key" 2048

# Generate self-signed certificate (valid for 1 year)
openssl req -new -x509 -days 365 -key "$TEMP_SSL_DIR/server.key" \
    -out "$TEMP_SSL_DIR/server.crt" \
    -subj "/C=US/ST=California/L=SF/O=SecureBank/OU=IT/CN=secure-db"

# Set ownership to postgres user and proper permissions
chown postgres:postgres "$TEMP_SSL_DIR/server.key" "$TEMP_SSL_DIR/server.crt"
chmod 600 "$TEMP_SSL_DIR/server.key"
chmod 644 "$TEMP_SSL_DIR/server.crt"

echo " SSL certificates generated successfully"
echo "    Certificate: $TEMP_SSL_DIR/server.crt"
echo "    Private Key: $TEMP_SSL_DIR/server.key"
echo "    Owner: postgres:postgres"

# Verify certificate
echo " Verifying SSL certificate..."
openssl x509 -in "$TEMP_SSL_DIR/server.crt" -noout -subject -dates

echo "================================================"
echo " SSL Setup Complete - Starting PostgreSQL"
echo "================================================"

# Export environment variables for the init script to use
export SSL_CERT_FILE="$TEMP_SSL_DIR/server.crt"
export SSL_KEY_FILE="$TEMP_SSL_DIR/server.key"

# Execute the original PostgreSQL entrypoint
# SSL will be enabled via postgresql.conf in the init script
exec docker-entrypoint.sh postgres