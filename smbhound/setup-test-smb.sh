#!/usr/bin/env bash

# Simple SMB test server setup script
# This sets up a minimal Samba server in the local directory

set -e

echo "Setting up minimal SMB test environment..."

# Create directory structure
mkdir -p ./smb-test/{config,shares/PublicShare,logs}

# Create minimal smb.conf
cat > ./smb-test/config/smb.conf << 'EOF'
[global]
    workgroup = TESTLAB
    server string = SMBHound Test Server
    security = user
    map to guest = bad user
    guest account = nobody
    
    # Use local directories (no system impact)
    private dir = ./smb-test/config
    lock directory = ./smb-test/config
    state directory = ./smb-test/config
    cache directory = ./smb-test/config
    pid directory = ./smb-test/config
    
    # Custom ports to avoid conflicts
    smb ports = 1445
    
    # Logging
    log file = ./smb-test/logs/samba.log
    log level = 2

[PublicShare]
    path = ./smb-test/shares/PublicShare
    browseable = yes
    read only = no
    guest ok = yes
    create mask = 0644
    directory mask = 0755
EOF

echo "✓ Samba configuration created"

# Create the share directory with proper permissions
chmod 755 ./smb-test/shares/PublicShare

echo "✓ Share directory created"

# Create a simple test structure with credentials
mkdir -p ./smb-test/shares/PublicShare/{documents,configs,binaries}

# Create some test files with credentials
cat > ./smb-test/shares/PublicShare/documents/readme.txt << 'EOF'
SMBHound Test Environment
==========================

This is a minimal test file for credential scanning.

Server Information:
- Hostname: test-server
- IP: 127.0.0.1
- Admin: testadmin
- Password: TestPass123

Please update the password regularly.
EOF

cat > ./smb-test/shares/PublicShare/configs/app.ini << 'EOF'
[Application]
Name=TestApp
Version=2.1.0
Environment=Production

[Database]
Host=localhost
Port=5432
Database=test_db
DBUser=app_user
DBPassword=SuperSecret123!
Timeout=30

[API]
Endpoint=https://api.example.com
ApiKey=sk_test_abc123def456ghi789
RateLimit=1000

[AdminAccounts]
Administrator=testadmin
AdminPassword=ComplexP@ss2025!
AdminEmail=admin@test.local
EOF

cat > ./smb-test/shares/PublicShare/configs/database.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <connectionStrings>
        <add name="MainDB" 
             connectionString="Server=localhost;Database=MainDB;User Id=dbuser;Password=XMLPass123!;" />
        <add name="ReportingDB" 
             connectionString="Server=localhost;Database=Reports;User Id=reports;Password=ReportP@ss;" />
    </connectionStrings>
    <credentials>
        <user name="admin" password="AdminXML2025!" />
        <user name="operator" password="OperatorPass" />
    </credentials>
</configuration>
EOF

# Create a simple binary with embedded credentials
cat > /tmp/test_app.c << 'EOF'
#include <stdio.h>

const char* API_KEY = "sk_hardcoded_api_key_abc123def456ghi789";
const char* DB_PASSWORD = "HardcodedDBPass2025!";
const char* ADMIN_PASS = "HardcodedAdmin123!";

int main() {
    printf("Test application with hardcoded credentials\n");
    return 0;
}
EOF

if command -v gcc >/dev/null 2>&1; then
    gcc /tmp/test_app.c -o ./smb-test/shares/PublicShare/binaries/application.exe
    echo "✓ Test binary created"
else
    echo "⚠ gcc not available, skipping binary creation"
fi

# Create a SQLite database with test data
if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 ./smb-test/shares/PublicShare/test.db << 'EOF'
CREATE TABLE credentials (
    id INTEGER PRIMARY KEY,
    service_name TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);

INSERT INTO credentials (service_name, username, password) VALUES
    ('Production Database', 'db_admin', 'DBCredential2025!'),
    ('API Gateway', 'api_admin', 'APIGateway123!');
EOF
    echo "✓ Test database created"
else
    echo "⚠ sqlite3 not available, skipping database creation"
fi

# Create a test archive
if command -v zip >/dev/null 2>&1; then
    mkdir -p /tmp/archive_test
    cat > /tmp/archive_test/credentials.txt << 'EOF'
Archived Credentials
====================

Username: archive_admin
Password: ArchivedPass2025!
EOF
    
    cd /tmp/archive_test
    zip -r "$(pwd)/../test_backup.zip" .
    cd - >/dev/null
    
    mv /tmp/test_backup.zip ./smb-test/shares/PublicShare/
    rm -rf /tmp/archive_test
    echo "✓ Test archive created"
else
    echo "⚠ zip not available, skipping archive creation"
fi

# Create summary file
cat > ./smb-test/shares/PublicShare/TEST_SUMMARY.txt << 'EOF'
SMBHound Minimal Test Environment
==================================

This share contains basic test files for validating SMBHound functionality.

CREDENTIALS TO FIND:
====================

TEXT FILES:
-----------
1. readme.txt - Password: TestPass123

CONFIG FILES (.ini):
-------------------
2. app.ini - DBPassword: SuperSecret123!
3. app.ini - ApiKey: sk_test_abc123def456ghi789
4. app.ini - AdminPassword: ComplexP@ss2025!

XML FILES:
----------
5. database.xml - Password: XMLPass123!
6. database.xml - Password: ReportP@ss
7. database.xml - password: AdminXML2025!
8. database.xml - password: OperatorPass

BINARY FILES (if gcc available):
--------------------------------
9. application.exe - API_KEY: sk_hardcoded_api_key_abc123def456ghi789
10. application.exe - DB_PASSWORD: HardcodedDBPass2025!
11. application.exe - ADMIN_PASS: HardcodedAdmin123!

DATABASE (if sqlite3 available):
---------------------------------
12. test.db - credentials table with passwords

ARCHIVE (if zip available):
---------------------------
13. test_backup.zip - Password: ArchivedPass2025!

Expected: 8-13 credentials depending on available tools
EOF

echo "✓ Test files created"

echo ""
echo "═══════════════════════════════════════"
echo "✓ Minimal SMB test environment ready!"
echo "═══════════════════════════════════════"
echo ""
echo "To start the SMB server:"
echo "  smbd -F -S -s ./smb-test/config/smb.conf"
echo ""
echo "To test SMBHound (in another terminal):"
echo "  python3 smbhound.py walk -t 127.0.0.1:1445 -u guest -p ''"
echo "  python3 smbhound.py talk --filetypes txt,ini,xml"
echo ""
echo "Note: Using custom port 1445 to avoid system conflicts"
echo "Guest access enabled for simplicity"
echo ""
echo "Share contents:"
find ./smb-test/shares/PublicShare -type f
echo "═══════════════════════════════════════"

# Cleanup
rm -f /tmp/test_app.c