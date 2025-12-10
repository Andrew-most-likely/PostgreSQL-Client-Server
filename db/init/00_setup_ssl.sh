#!/bin/bash
set -e

echo "🔧 Configuring PostgreSQL SSL..."

# Copy SSL certificates from temp location to data directory
if [ -f "$SSL_CERT_FILE" ] && [ -f "$SSL_KEY_FILE" ]; then
    cp "$SSL_CERT_FILE" "$PGDATA/server.crt"
    cp "$SSL_KEY_FILE" "$PGDATA/server.key"
    
    chown postgres:postgres "$PGDATA/server.crt" "$PGDATA/server.key"
    chmod 600 "$PGDATA/server.key"
    chmod 644 "$PGDATA/server.crt"
    
    echo "✅ SSL certificates copied to data directory"
    
    # Configure PostgreSQL to use SSL
    echo "ssl = on" >> "$PGDATA/postgresql.conf"
    echo "ssl_cert_file = 'server.crt'" >> "$PGDATA/postgresql.conf"
    echo "ssl_key_file = 'server.key'" >> "$PGDATA/postgresql.conf"
    
    # Require SSL for non-local connections
    echo "hostssl all all 0.0.0.0/0 scram-sha-256" >> "$PGDATA/pg_hba.conf"
    
    echo "✅ PostgreSQL configured for SSL"
else
    echo "⚠️  SSL certificates not found, SSL not enabled"
fi