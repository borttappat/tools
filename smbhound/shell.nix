# Complete SMBHound development environment
{ pkgs ? import <nixpkgs> {} }:

let
  # Helper scripts for the development environment
  setupTestFiles = pkgs.writeScriptBin "setup-test-files" ''
    #!/usr/bin/env bash
    set -e
    
    echo "🔧 Setting up SMBHound test environment..."
    
    # Create persistent directories
    mkdir -p smb-test/{config,shares,logs}
    mkdir -p smb-test/shares/{PublicShare,AdminShare,RestrictedShare}
    
    # Create test file structure
    mkdir -p smb-test/shares/PublicShare/{documents,configs,binaries,archives,databases}
    mkdir -p smb-test/shares/AdminShare/{secrets,backups}
    mkdir -p smb-test/shares/RestrictedShare/{classified}
    
    # Generate Samba configuration
    cat > smb-test/config/smb.conf << 'EOF'
[global]
    workgroup = TESTLAB
    server string = SMBHound Test Server
    security = user
    map to guest = bad user
    guest account = nobody
    
    # Use local directories
    private dir = $(pwd)/smb-test/config
    lock directory = $(pwd)/smb-test/config
    state directory = $(pwd)/smb-test/config
    cache directory = $(pwd)/smb-test/config
    pid directory = $(pwd)/smb-test/config
    
    # Logging
    log file = $(pwd)/smb-test/logs/samba.log
    log level = 2
    max log size = 1000

[PublicShare]
    path = $(pwd)/smb-test/shares/PublicShare
    browseable = yes
    read only = no
    guest ok = yes
    create mask = 0644
    directory mask = 0755

[AdminShare]
    path = $(pwd)/smb-test/shares/AdminShare
    browseable = yes
    read only = no
    guest ok = no
    valid users = admin
    create mask = 0600
    directory mask = 0700

[RestrictedShare]
    path = $(pwd)/smb-test/shares/RestrictedShare
    browseable = yes
    read only = no
    guest ok = no
    valid users = restricted
    create mask = 0600
    directory mask = 0700
EOF

    # Set up directory permissions
    chmod 755 smb-test/shares/PublicShare
    chmod 755 smb-test/shares/AdminShare
    chmod 755 smb-test/shares/RestrictedShare
    
    echo "✓ SMB configuration created"
    echo "✓ Directory structure ready"
    echo ""
    echo "Next steps:"
    echo "  1. Run 'create-test-data' to generate test files with credentials"
    echo "  2. Run 'start-smb-server' to start the SMB server"
    echo "  3. Test with 'test-smbhound'"
  '';

  createTestData = pkgs.writeScriptBin "create-test-data" ''
    #!/usr/bin/env bash
    set -e
    
    if [ ! -d "smb-test/shares/PublicShare" ]; then
      echo "❌ Test environment not set up. Run 'setup-test-files' first."
      exit 1
    fi
    
    echo "📝 Creating test files with embedded credentials..."
    
    BASE_DIR="smb-test/shares/PublicShare"
    
    # Text files with credentials
    cat > "$BASE_DIR/documents/readme.txt" << 'EOF'
SMBHound Test Environment
=========================

Server credentials:
- Username: testadmin
- Password: TestPass123!
- Server: test-server.local

Contact admin@corp.local for access.
EOF

    cat > "$BASE_DIR/documents/notes.txt" << 'EOF'
Meeting Notes - 2025-11-09
===========================

System Migration:
- Old admin account: svc_legacy
- Legacy password: LegacyP@ss2025
- New system uses SSO

Database Migration:
- DB Admin: db_migrate
- Temp Password: MigrateDB123!
- Remember to rotate after migration

API Keys:
- Production: sk_prod_abc123def456ghi789
- Staging: sk_stage_xyz789abc123def456
EOF

    # Config files
    cat > "$BASE_DIR/configs/app.ini" << 'EOF'
[Application]
Name=TestApp
Version=2.1.0
Environment=Production

[Database]
Host=db.corp.local
Port=5432
Database=production
DBUser=app_user
DBPassword=AppDB2025!
ConnectionTimeout=30

[API]
BaseURL=https://api.corp.local
ApiKey=sk_live_abcdef123456789
ApiSecret=secret_xyz789abc123
RateLimit=1000

[LDAP]
Server=ldap://dc.corp.local
BindDN=CN=svc_app,OU=Services,DC=corp,DC=local
BindPassword=ServiceAccount2025!
BaseDN=DC=corp,DC=local

[AdminAccounts]
EmergencyAdmin=emergency_admin
EmergencyPassword=Emergency123!
SupportUser=support_user
SupportPassword=Support2025!
EOF

    cat > "$BASE_DIR/configs/database.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <connectionStrings>
        <add name="ProductionDB" 
             connectionString="Server=sql01.corp.local;Database=ProdDB;User Id=sa;Password=SQLAdmin2025!;Encrypt=True;" />
        <add name="ReportsDB" 
             connectionString="Server=sql02.corp.local;Database=Reports;User Id=reports;Password=ReportsP@ss123;" />
        <add name="AuditDB" 
             connectionString="Server=sql03.corp.local;Database=Audit;User Id=auditor;Password=AuditPass2025!;" />
    </connectionStrings>
    <appSettings>
        <add key="EncryptionKey" value="encryption_secret_key_do_not_share_xyz789" />
        <add key="JWTSecret" value="jwt_signing_key_abc123def456ghi789" />
    </appSettings>
    <credentials>
        <user name="admin" password="XMLAdmin2025!" role="Administrator" />
        <user name="operator" password="Operator123!" role="Operator" />
        <user name="readonly" password="ReadOnly2025!" role="Reader" />
    </credentials>
</configuration>
EOF

    # Create a binary with embedded strings
    if command -v gcc >/dev/null 2>&1; then
      cat > /tmp/test_binary.c << 'EOF'
#include <stdio.h>
#include <string.h>

const char* API_KEY = "sk_binary_embedded_abc123def456ghi789jkl012";
const char* DB_PASSWORD = "BinaryEmbeddedPass2025!";
const char* ADMIN_USER = "binary_admin";
const char* ADMIN_PASS = "BinaryAdmin123!";
const char* SECRET_TOKEN = "Bearer_eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0";
const char* CONNECTION_STRING = "Server=binary.corp.local;Database=BinaryDB;User=binary_user;Password=BinaryDBPass2025!;";

int main() {
    printf("SMBHound Test Binary\n");
    printf("Version: 1.0.0\n");
    
    // Simulate some authentication logic
    char input[256];
    printf("Enter command: ");
    if (fgets(input, sizeof(input), stdin)) {
        if (strstr(input, "debug")) {
            printf("Debug mode activated\n");
            printf("API Endpoint: %s\n", API_KEY);
        } else if (strstr(input, "admin")) {
            printf("Admin access: %s:%s\n", ADMIN_USER, ADMIN_PASS);
        } else {
            printf("Unknown command\n");
        }
    }
    
    return 0;
}
EOF

      gcc /tmp/test_binary.c -o "$BASE_DIR/binaries/testapp.exe" 2>/dev/null || echo "⚠ gcc not available, skipping binary"
      rm -f /tmp/test_binary.c
    fi
    
    # Create SQLite database
    if command -v sqlite3 >/dev/null 2>&1; then
      sqlite3 "$BASE_DIR/databases/users.db" << 'EOF'
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE credentials (
    id INTEGER PRIMARY KEY,
    service_name TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY,
    application TEXT NOT NULL,
    api_key TEXT NOT NULL,
    api_secret TEXT,
    permissions TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert test data
INSERT INTO users (username, password_hash, email) VALUES 
    ('admin', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8', 'admin@corp.local'),
    ('user1', '$2b$12$EixZaYVK1fsbw1ZfbX3OXe', 'user1@corp.local'),
    ('service', '$2b$12$GixZaYVK1fsbw1ZfbX3OYe', 'service@corp.local');

INSERT INTO credentials (service_name, username, password, notes) VALUES
    ('Production Database', 'db_prod', 'DBProduction2025!', 'Main production database access'),
    ('File Server', 'file_admin', 'FileAdmin123!', 'Network file server administrator'),
    ('Backup System', 'backup_svc', 'BackupService2025!', 'Automated backup service account'),
    ('Monitoring', 'monitor_user', 'Monitor123!', 'System monitoring dashboard'),
    ('VPN Gateway', 'vpn_admin', 'VPNAdmin2025!', 'VPN gateway management');

INSERT INTO api_keys (application, api_key, api_secret, permissions) VALUES
    ('Production API', 'sk_prod_xyz789abc123def456ghi789jkl012mno345', 'secret_prod_abc123', 'read,write,admin'),
    ('Analytics API', 'sk_analytics_def456ghi789jkl012mno345pqr678', 'secret_analytics_def456', 'read'),
    ('Integration API', 'sk_integration_ghi789jkl012mno345pqr678stu901', 'secret_integration_ghi789', 'read,write');
EOF
    else
      echo "⚠ sqlite3 not available, skipping database creation"
    fi
    
    # Create archive with credentials
    if command -v zip >/dev/null 2>&1; then
      mkdir -p /tmp/archive_content
      cat > /tmp/archive_content/archived_secrets.txt << 'EOF'
Archived System Credentials
===========================

Legacy Systems:
- Old CRM: crm_admin / CRMPass2025!
- Legacy DB: legacy_user / LegacyDB123!
- Archive Server: archive_admin / ArchivePass2025!

Decommissioned Services:
- Old API: api_legacy / LegacyAPI123!
- Test Environment: test_admin / TestEnvPass2025!
EOF

      cat > /tmp/archive_content/backup_config.ini << 'EOF'
[BackupCredentials]
BackupServer=backup.corp.local
BackupUser=backup_operator
BackupPassword=BackupOperator2025!

[ArchiveSettings]
ArchiveLocation=\\\\archive.corp.local\\backups
ArchiveUser=archive_service
ArchivePassword=ArchiveService123!
EOF

      cd /tmp/archive_content
      zip -r "$BASE_DIR/archives/backup_configs.zip" . >/dev/null 2>&1
      cd - >/dev/null
      rm -rf /tmp/archive_content
    else
      echo "⚠ zip not available, skipping archive creation"
    fi
    
    # Create admin share files
    mkdir -p smb-test/shares/AdminShare/secrets
    cat > smb-test/shares/AdminShare/secrets/domain_admin.ini << 'EOF'
[DomainAdministration]
DomainController=dc01.corp.local
DomainAdmin=CORP\\Administrator
DomainPassword=DomainAdmin2025!
SafeModePassword=SafeMode123!

[ServiceAccounts]
BackupService=CORP\\svc_backup
BackupPassword=DomainBackup2025!
SQLService=CORP\\svc_sql
SQLPassword=SQLService2025!
ExchangeService=CORP\\svc_exchange
ExchangePassword=ExchangeService2025!
EOF
    
    # Set appropriate permissions
    chmod 644 "$BASE_DIR"/{documents,configs,databases,archives}/* 2>/dev/null || true
    chmod +x "$BASE_DIR/binaries"/* 2>/dev/null || true
    chmod 600 smb-test/shares/AdminShare/secrets/* 2>/dev/null || true
    
    # Create summary
    cat > "$BASE_DIR/TEST_SUMMARY.txt" << 'EOF'
SMBHound Test Environment - Credentials Summary
===============================================

This test environment contains 20+ embedded credentials for testing:

TEXT FILES (documents/):
- readme.txt: testadmin / TestPass123!
- notes.txt: svc_legacy / LegacyP@ss2025, db_migrate / MigrateDB123!
- notes.txt: API Keys: sk_prod_abc123def456ghi789, sk_stage_xyz789abc123def456

CONFIG FILES (configs/):
- app.ini: app_user / AppDB2025!, API key, emergency_admin / Emergency123!
- app.ini: svc_app / ServiceAccount2025!, support_user / Support2025!
- database.xml: sa / SQLAdmin2025!, reports / ReportsP@ss123
- database.xml: auditor / AuditPass2025!, admin / XMLAdmin2025!

BINARY FILES (binaries/):
- testapp.exe: Binary strings with embedded API keys and passwords

DATABASE (databases/):
- users.db: 5 service accounts with plaintext passwords in credentials table
- users.db: 3 API keys with secrets in api_keys table

ARCHIVES (archives/):
- backup_configs.zip: Contains archived credentials and config files

ADMIN SHARE (AdminShare/secrets/):
- domain_admin.ini: Domain Administrator and service account passwords

Expected Results:
- 20+ unique credentials across different file types
- Multiple file formats: txt, ini, xml, exe, db, zip
- Different encoding contexts (plaintext, config files, binary strings)
- Realistic credential patterns and formats

Perfect for testing SMBHound's detection capabilities!
EOF
    
    echo "✓ Test files created successfully"
    echo "✓ Credentials embedded in multiple file types"
    echo "✓ Summary available at: smb-test/shares/PublicShare/TEST_SUMMARY.txt"
    echo ""
    echo "Files created:"
    find smb-test/shares -type f | sort
    echo ""
    echo "Ready to start SMB server with: start-smb-server"
  '';

  startSMBServer = pkgs.writeScriptBin "start-smb-server" ''
    #!/usr/bin/env bash
    set -e
    
    if [ ! -f "smb-test/config/smb.conf" ]; then
      echo "❌ SMB configuration not found. Run 'setup-test-files' first."
      exit 1
    fi
    
    echo "🚀 Starting SMB server..."
    echo "Configuration: $(pwd)/smb-test/config/smb.conf"
    echo "Shares: PublicShare (guest), AdminShare (admin), RestrictedShare (restricted)"
    echo ""
    echo "To stop the server: Press Ctrl+C"
    echo "To test: run 'test-smbhound' in another terminal"
    echo ""
    echo "Server starting..."
    
    # Start SMB daemon in foreground
    smbd -F -S -s "$(pwd)/smb-test/config/smb.conf"
  '';

  testSMBHound = pkgs.writeScriptBin "test-smbhound" ''
    #!/usr/bin/env bash
    set -e
    
    echo "🔍 Testing SMBHound..."
    echo ""
    
    # Check if SMB server is running
    if ! nc -z 127.0.0.1 445 2>/dev/null; then
      echo "❌ SMB server not running on port 445"
      echo "Start it with: start-smb-server"
      exit 1
    fi
    
    echo "✓ SMB server is running"
    echo ""
    echo "Running SMBHound walk phase..."
    
    # Run walk phase
    python3 smbhound.py walk -t 127.0.0.1 -u guest -p ""
    
    if [ $? -eq 0 ]; then
      echo ""
      echo "✓ Walk phase completed successfully"
      echo "📋 Index file created: smb_index_127.0.0.1.txt"
      echo ""
      echo "Running SMBHound talk phase..."
      
      # Run talk phase
      python3 smbhound.py talk --filetypes txt,ini,xml --keywords-inline "password,pass,secret,key,admin,api"
      
      if [ $? -eq 0 ]; then
        echo ""
        echo "🎉 SMBHound test completed successfully!"
        echo ""
        echo "Check results:"
        echo "  - Human-readable index: smb_index_127.0.0.1.txt"
        echo "  - Downloaded files: downloads_127.0.0.1/"
        echo "  - Search results: downloads_127.0.0.1/by_type/*/RESULTS.txt"
        echo ""
        echo "Example: cat downloads_127.0.0.1/by_type/ini/RESULTS.txt"
      else
        echo "❌ Talk phase failed"
      fi
    else
      echo "❌ Walk phase failed"
    fi
  '';

  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    pip
    setuptools
    wheel
    virtualenv
  ]);

in

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Python environment
    pythonEnv
    
    # SMB server and client tools
    samba
    cifs-utils
    
    # System dependencies for python-magic and file analysis
    file
    
    # Tools for creating test files
    sqlite
    gcc
    binutils
    zip
    p7zip
    
    # Network utilities
    netcat-gnu
    procps
    iproute2
    tree
    
    # Helper scripts
    setupTestFiles
    createTestData
    startSMBServer
    testSMBHound
  ];

  shellHook = ''
    echo "🔍 SMBHound Complete Development Environment"
    echo "==========================================="
    echo ""
    echo "Setting up Python environment..."
    
    # Create venv if it doesn't exist
    if [ ! -d "venv" ]; then
      python3 -m venv venv
      echo "✓ Virtual environment created"
    fi
    
    # Activate venv
    source venv/bin/activate
    echo "✓ Virtual environment activated"
    
    # Install dependencies if needed
    if [ -f "requirements.txt" ] && [ ! -f "venv/.deps_installed" ]; then
      echo "Installing SMBHound dependencies..."
      pip install --upgrade pip
      pip install -r requirements.txt
      touch venv/.deps_installed
      echo "✓ Dependencies installed"
    fi
    
    echo ""
    echo "Available commands:"
    echo "  setup-test-files  - Create SMB test environment"
    echo "  create-test-data  - Generate test files with credentials"
    echo "  start-smb-server  - Start SMB server (blocking)"
    echo "  test-smbhound     - Run full SMBHound test"
    echo ""
    echo "Quick start:"
    echo "  1. setup-test-files"
    echo "  2. create-test-data"
    echo "  3. start-smb-server     (in one terminal)"
    echo "  4. test-smbhound        (in another terminal)"
    echo ""
    echo "Manual testing:"
    echo "  python3 smbhound.py walk -t 127.0.0.1 -u guest -p \"\""
    echo "  python3 smbhound.py talk --filetypes txt,ini,xml"
    echo ""
    echo "Environment ready! 🚀"
    echo ""
  '';
}