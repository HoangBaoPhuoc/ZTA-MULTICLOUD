#!/bin/bash
#===============================================================================
# ZTA Multi-Cloud SSH Helper
# Tổng hợp tất cả SSH commands để truy cập các thành phần trong hệ thống
#===============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# SSH Key
SSH_KEY="$HOME/.ssh/id_rsa_zerotrust"

# External IPs (Floating IPs) - ONLY Auth Portal has public IP
AUTH_PORTAL_IP="172.10.10.170"

# Internal IPs (qua ProxyCommand via Auth Portal)
MONITORING_IP="10.40.1.10"
IDENTITY_IP="10.40.1.20"
AWS_GATEWAY_IP="10.20.2.5"
AWS_MASTER_IP="10.20.2.10"
OS_GATEWAY_IP="10.10.2.5"
OS_MASTER_IP="10.10.2.10"

show_menu() {
    clear
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║         🔐 ZTA MULTI-CLOUD SSH HELPER                         ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  SSH Key: ${YELLOW}~/.ssh/id_rsa_zerotrust${CYAN}                            ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  ${GREEN}TRUY CẬP TRỰC TIẾP (ONLY public entry point):${CYAN}                ║${NC}"
    echo -e "${CYAN}║    1) Auth Portal      ${YELLOW}172.10.10.170${CYAN}  (THE ONLY public IP)   ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  ${GREEN}TRUY CẬP QUA PROXY (Zero Trust - all via Auth Portal):${CYAN}       ║${NC}"
    echo -e "${CYAN}║    2) Monitoring       ${YELLOW}10.40.1.10${CYAN}  (Grafana/Prometheus)      ║${NC}"
    echo -e "${CYAN}║    3) Identity         ${YELLOW}10.40.1.20${CYAN}  (Keycloak/SPIRE)          ║${NC}"
    echo -e "${CYAN}║    4) AWS Gateway      ${YELLOW}10.20.2.5${CYAN}   (Envoy/OPA)               ║${NC}"
    echo -e "${CYAN}║    5) AWS Master       ${YELLOW}10.20.2.10${CYAN}  (K3s cluster)             ║${NC}"
    echo -e "${CYAN}║    6) OS Gateway       ${YELLOW}10.10.2.5${CYAN}   (Envoy/OPA)               ║${NC}"
    echo -e "${CYAN}║    7) OS Master        ${YELLOW}10.10.2.10${CYAN}  (K3s cluster)             ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║  ${GREEN}QUICK COMMANDS:${CYAN}                                              ║${NC}"
    echo -e "${CYAN}║    8) AWS Cluster - kubectl get pods -A                       ║${NC}"
    echo -e "${CYAN}║    9) OS Cluster  - kubectl get pods -A                       ║${NC}"
    echo -e "${CYAN}║    c) Check all services                                      ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║    0) Exit                                                    ║${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

ssh_direct() {
    local host=$1
    local name=$2
    echo -e "${GREEN}🔗 Connecting to $name ($host)...${NC}"
    ssh -o StrictHostKeyChecking=no -i "$SSH_KEY" ubuntu@"$host"
}

ssh_proxy() {
    local host=$1
    local name=$2
    echo -e "${GREEN}🔗 Connecting to $name ($host) via Auth Portal...${NC}"
    ssh -o StrictHostKeyChecking=no \
        -o "ProxyCommand=ssh -o StrictHostKeyChecking=no -W %h:%p -i $SSH_KEY ubuntu@$AUTH_PORTAL_IP" \
        -i "$SSH_KEY" ubuntu@"$host"
}

run_remote_cmd() {
    local host=$1
    local cmd=$2
    local name=$3
    echo -e "${GREEN}🚀 Running on $name ($host): $cmd${NC}"
    echo "----------------------------------------"
    ssh -o StrictHostKeyChecking=no \
        -o "ProxyCommand=ssh -o StrictHostKeyChecking=no -W %h:%p -i $SSH_KEY ubuntu@$AUTH_PORTAL_IP" \
        -i "$SSH_KEY" ubuntu@"$host" "$cmd"
    echo ""
    read -p "Press Enter to continue..."
}

check_all_services() {
    echo -e "${CYAN}=== Checking All ZTA Services (Zero Trust) ===${NC}"
    echo ""
    
    echo -e "${YELLOW}[1/4] Auth Portal (172.10.10.170:8888) - Direct${NC}"
    curl -s --connect-timeout 3 http://172.10.10.170:8888/health 2>/dev/null && echo -e "${GREEN}✓ OK${NC}" || echo -e "${RED}✗ FAILED${NC}"
    
    echo -e "${YELLOW}[2/4] Grafana via Auth Portal (/grafana/)${NC}"
    # Grafana no longer has public IP - access via Auth Portal proxy
    curl -s --connect-timeout 3 http://172.10.10.170/grafana/api/health 2>/dev/null && echo -e "${GREEN}✓ OK${NC}" || echo -e "${YELLOW}⚠ Proxy not configured yet${NC}"
    
    echo -e "${YELLOW}[3/4] Prometheus via SSH tunnel${NC}"
    # Access Prometheus via SSH tunnel
    echo -e "${CYAN}  (Access via: ssh -L 9090:10.40.1.10:9090 ubuntu@172.10.10.170)${NC}"
    
    echo -e "${YELLOW}[4/4] AWS Cluster Pods${NC}"
    ssh -o StrictHostKeyChecking=no \
        -o "ProxyCommand=ssh -o StrictHostKeyChecking=no -W %h:%p -i $SSH_KEY ubuntu@$AUTH_PORTAL_IP" \
        -i "$SSH_KEY" ubuntu@"$AWS_MASTER_IP" "kubectl get pods -A --no-headers 2>/dev/null | wc -l" 2>/dev/null
    
    echo ""
    read -p "Press Enter to continue..."
}

# Print quick reference
print_quick_ref() {
    echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    📋 QUICK SSH REFERENCE (Zero Trust)                    ║${NC}"
    echo -e "${CYAN}╠════════════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${CYAN}║ ${GREEN}# ONLY Auth Portal has public IP:${NC}"
    echo -e "${CYAN}║ ${YELLOW}ssh -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170  ${NC}# Auth Portal"
    echo -e "${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}# ALL other VMs via ProxyCommand:${NC}"
    echo -e "${CYAN}║ ${YELLOW}ssh -o ProxyCommand=\"ssh -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170\" \\${NC}"
    echo -e "${CYAN}║ ${YELLOW}    -i ~/.ssh/id_rsa_zerotrust ubuntu@10.40.1.10  ${NC}# Monitoring"
    echo -e "${CYAN}║${NC}"
    echo -e "${CYAN}║ ${GREEN}# Port forwarding for Grafana:${NC}"
    echo -e "${CYAN}║ ${YELLOW}ssh -L 3000:10.40.1.10:3000 -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170${NC}"
    echo -e "${CYAN}║ ${YELLOW}# Then open: http://localhost:3000${NC}"
    echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════════╝${NC}"
}

# Main
if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    print_quick_ref
    exit 0
fi

if [[ "$1" == "-q" ]] || [[ "$1" == "--quick" ]]; then
    print_quick_ref
    exit 0
fi

# Check SSH key exists
if [[ ! -f "$SSH_KEY" ]]; then
    echo -e "${RED}❌ SSH Key not found: $SSH_KEY${NC}"
    echo -e "${YELLOW}Please ensure the key exists or update SSH_KEY variable${NC}"
    exit 1
fi

# Interactive menu
while true; do
    show_menu
    read -p "Select option [0-9,c]: " choice
    
    case $choice in
        1) ssh_direct "$AUTH_PORTAL_IP" "Auth Portal" ;;
        2) ssh_proxy "$MONITORING_IP" "Monitoring" ;;
        3) ssh_proxy "$IDENTITY_IP" "Identity" ;;
        4) ssh_proxy "$AWS_GATEWAY_IP" "AWS Gateway" ;;
        5) ssh_proxy "$AWS_MASTER_IP" "AWS Master" ;;
        6) ssh_proxy "$OS_GATEWAY_IP" "OS Gateway" ;;
        7) ssh_proxy "$OS_MASTER_IP" "OS Master" ;;
        8) run_remote_cmd "$AWS_MASTER_IP" "kubectl get pods -A" "AWS Master" ;;
        9) run_remote_cmd "$OS_MASTER_IP" "kubectl get pods -A" "OS Master" ;;
        c|C) check_all_services ;;
        0) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
    esac
done
