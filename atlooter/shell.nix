{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  name = "atlooter";

  buildInputs = with pkgs.python3.pkgs; [
    atlassian-python-api
    requests
    pyyaml
    python-dateutil
    tqdm
    python-dotenv
    rich
  ];

  shellHook = ''
    echo "============================================"
    echo "  atlooter - Atlassian Forensics Collector"
    echo "============================================"
    echo ""
    echo "Python: $(python --version)"
    echo ""
    echo "Available packages:"
    echo "  - atlassian (Confluence & Jira API client)"
    echo "  - requests (HTTP requests)"
    echo "  - pyyaml (YAML config parsing)"
    echo "  - python-dateutil (Timestamp handling)"
    echo "  - tqdm (Progress bars)"
    echo "  - python-dotenv (Environment variables)"
    echo "  - rich (Rich output formatting)"
    echo ""
    echo "To start collection:"
    echo "  1. Set your credentials:"
    echo "     export CONFLUENCE_URL=https://your-domain.atlassian.net"
    echo "     export CONFLUENCE_EMAIL=your-email@company.com"
    echo "     export CONFLUENCE_TOKEN=your-api-token"
    echo ""
    echo "     export JIRA_URL=https://your-domain.atlassian.net"
    echo "     export JIRA_EMAIL=your-email@company.com"
    echo "     export JIRA_TOKEN=your-api-token"
    echo ""
    echo "  2. Run the collectors:"
    echo "     python scripts/run_confluence.py"
    echo "     python scripts/run_jira.py"
    echo ""
  '';
}
