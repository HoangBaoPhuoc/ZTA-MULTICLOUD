#!/bin/bash
################################################################################
# ZTA Hub-and-Spoke Full Deployment v7.0
# Architecture:
#   - Auth Portal: Login UI only → Issue JWT → Redirect to AWS Gateway
#   - AWS Gateway: OPA+Envoy (Protect UI access with JWT validation)
#   - AWS Cluster: UI Pods (K8s NodePort 30080) - Only accessible after JWT
#   - OS Gateway: Envoy mTLS termination
#   - OS Cluster: Backend API Pods (K8s NodePort 30090)
#   - mTLS between AWS Gateway ↔ OS Gateway
################################################################################
set -e
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

BASE_DIR="/etc/zta-multicloud"
TERRAFORM_DIR="$BASE_DIR/terraform-openstack"
ANSIBLE_DIR="$BASE_DIR/ansible-zta"
INVENTORY_FILE="$ANSIBLE_DIR/inventory/hosts.ini"

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Parse arguments
SKIP_TERRAFORM=false
SKIP_ANSIBLE=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --skip-terraform) SKIP_TERRAFORM=true ;;
        --skip-ansible) SKIP_ANSIBLE=true ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-terraform     Skip Terraform phase"
            echo "  --skip-ansible       Skip Ansible phase"
            echo "  --help               Show this help"
            exit 0
            ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# Check OpenStack credentials
check_openstack_auth() {
    if [ -z "$OS_AUTH_URL" ]; then
        log_error "OpenStack credentials not found!"
        log "Please source your OpenStack RC file"
        exit 1
    fi
    log "OpenStack: $OS_PROJECT_NAME @ $OS_AUTH_URL"
    if ! openstack token issue >/dev/null 2>&1; then
        log_error "OpenStack authentication failed!"
        exit 1
    fi
    log_success "OpenStack auth OK"
}

# 1. Terraform
deploy_terraform() {
    if [ "$SKIP_TERRAFORM" == "true" ]; then
        log "Skipping Terraform"
    else
        log "STEP 1: Terraform"
        check_openstack_auth
        cd "$TERRAFORM_DIR" || exit 1
        terraform init -upgrade >/dev/null 2>&1
        terraform apply -auto-approve
    fi
    
    cd "$TERRAFORM_DIR" || exit 1
    
    # IPs - Hub-and-Spoke architecture (Zero Trust: ONLY Auth Portal has public IP)
    AUTH_PORTAL_IP="172.10.10.170"
    MON_IP="10.40.1.10"  # NO public IP - access via SSH tunnel
    IDENTITY_IP="10.40.1.20"
    AWS_GW="10.20.2.5"
    OS_GW="10.10.2.5"
    AWS_CLUSTER="10.20.2.10"
    OS_CLUSTER="10.10.2.10"
    
    cat > /tmp/zta-ips.env << EOF
AUTH_PORTAL_IP=$AUTH_PORTAL_IP
MON_IP=$MON_IP
IDENTITY_IP=$IDENTITY_IP
AWS_GW=$AWS_GW
OS_GW=$OS_GW
AWS_CLUSTER=$AWS_CLUSTER
OS_CLUSTER=$OS_CLUSTER
EOF
    log_success "IPs configured (Zero Trust: Only Auth Portal has public IP)"
}

# 2. Generate Inventory
generate_inventory() {
    log "STEP 2: Generating Inventory"
    source /tmp/zta-ips.env
    
    for IP in $AUTH_PORTAL_IP $MON_IP $IDENTITY_IP $AWS_GW $OS_GW $AWS_CLUSTER $OS_CLUSTER; do
        ssh-keygen -f "$HOME/.ssh/known_hosts" -R "$IP" 2>/dev/null || true
    done
    
    mkdir -p "$(dirname "$INVENTORY_FILE")"
    cat > "$INVENTORY_FILE" << EOF
[all:vars]
ansible_user=ubuntu
ansible_ssh_private_key_file=~/.ssh/id_rsa_zerotrust
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

auth_portal_public_ip=$AUTH_PORTAL_IP
monitoring_internal_ip=$MON_IP
identity_internal_ip=$IDENTITY_IP
aws_gateway_internal_ip=$AWS_GW
os_gateway_internal_ip=$OS_GW

[vm_auth_portal]
vm-auth-portal ansible_host=$AUTH_PORTAL_IP

[vm_identity]
vm-identity ansible_host=$IDENTITY_IP ansible_ssh_common_args='-o StrictHostKeyChecking=no -o ProxyCommand="ssh -o StrictHostKeyChecking=no -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@$AUTH_PORTAL_IP"'

[vm_monitoring]
# Zero Trust: NO public IP - access via SSH ProxyCommand
vm-monitoring ansible_host=$MON_IP ansible_ssh_common_args='-o StrictHostKeyChecking=no -o ProxyCommand="ssh -o StrictHostKeyChecking=no -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@$AUTH_PORTAL_IP"'

[vm_gateway]
vm-aws-gateway ansible_host=$AWS_GW ansible_ssh_common_args='-o StrictHostKeyChecking=no -o ProxyCommand="ssh -o StrictHostKeyChecking=no -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@$AUTH_PORTAL_IP"'
vm-os-gateway  ansible_host=$OS_GW ansible_ssh_common_args='-o StrictHostKeyChecking=no -o ProxyCommand="ssh -o StrictHostKeyChecking=no -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@$AUTH_PORTAL_IP"'

[k3s_masters]
aws-master ansible_host=$AWS_CLUSTER ansible_ssh_common_args='-o StrictHostKeyChecking=no -o ProxyCommand="ssh -o StrictHostKeyChecking=no -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@$AUTH_PORTAL_IP"'
os-master  ansible_host=$OS_CLUSTER ansible_ssh_common_args='-o StrictHostKeyChecking=no -o ProxyCommand="ssh -o StrictHostKeyChecking=no -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@$AUTH_PORTAL_IP"'
EOF
    log_success "Inventory: $INVENTORY_FILE (Zero Trust: Only Auth Portal has public IP)"
}

# 3. Wait for VMs
wait_for_vms() {
    log "STEP 3: Checking VMs"
    source /tmp/zta-ips.env
    
    # Only check Auth Portal directly (the only public IP)
    log "Checking Auth Portal ($AUTH_PORTAL_IP)..."
    for i in {1..30}; do
        if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -i ~/.ssh/id_rsa_zerotrust ubuntu@$AUTH_PORTAL_IP "echo OK" 2>/dev/null; then
            log_success "$AUTH_PORTAL_IP ready"
            break
        fi
        [ $i -eq 30 ] && log_warn "$AUTH_PORTAL_IP timeout"
        sleep 5
    done
    
    # Check Monitoring via SSH ProxyCommand (no public IP)
    log "Checking Monitoring ($MON_IP via Auth Portal)..."
    for i in {1..10}; do
        if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
            -o "ProxyCommand=ssh -o StrictHostKeyChecking=no -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@$AUTH_PORTAL_IP" \
            -i ~/.ssh/id_rsa_zerotrust ubuntu@$MON_IP "echo OK" 2>/dev/null; then
            log_success "$MON_IP ready (via proxy)"
            break
        fi
        [ $i -eq 10 ] && log_warn "$MON_IP timeout"
        sleep 5
    done
}

# 4. Deploy with Ansible
deploy_ansible() {
    [ "$SKIP_ANSIBLE" == "true" ] && { log "Skipping Ansible"; return; }
    
    log "STEP 4: Ansible Deployment"
    cd "$ANSIBLE_DIR" || exit 1
    
    ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i "$INVENTORY_FILE" deploy-zta-hub-spoke.yml -v
    
    [ $? -eq 0 ] && log_success "Ansible OK" || { log_error "Ansible failed"; exit 1; }
}

# 5. Verify
verify_deployment() {
    log "STEP 5: Verifying"
    source /tmp/zta-ips.env
    
    AUTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://$AUTH_PORTAL_IP/ 2>/dev/null || echo "000")
    [ "$AUTH_STATUS" == "200" ] && log_success "Auth Portal OK" || log_warn "Auth Portal: $AUTH_STATUS"
}

# 6. Results
show_results() {
    source /tmp/zta-ips.env
    
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║        ZTA HUB-AND-SPOKE DEPLOYMENT COMPLETED!               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${CYAN}Architecture:${NC}"
    echo -e "  User → Auth Portal (Login) → Get JWT"
    echo -e "       → Redirect to AWS Gateway:8080/dashboard"
    echo -e "       → OPA validates JWT → Allow/Deny"
    echo -e "       → AWS Cluster UI Pods (K8s)"
    echo -e "       → UI fetches /api/backend"
    echo -e "       → AWS Gateway (mTLS) → OS Gateway"
    echo -e "       → OS Cluster Backend Pods (K8s)"
    echo ""
    echo -e "${BLUE}Access:${NC}"
    echo -e "  🔐 Login:     ${YELLOW}http://$AUTH_PORTAL_IP/${NC}"
    echo -e "  📊 Dashboard: ${YELLOW}http://$AWS_GW:8080/dashboard${NC} (needs JWT)"
    echo ""
    echo -e "${BLUE}Credentials:${NC}"
    echo -e "  admin / admin123      - Full access"
    echo -e "  aws_user / aws123     - AWS only"
    echo -e "  full_user / full123   - Full read"
    echo ""
    echo -e "${BLUE}Test:${NC}"
    echo -e "  1. Open ${YELLOW}http://$AUTH_PORTAL_IP/${NC}"
    echo -e "  2. Login → Redirect to Dashboard"
    echo -e "  3. Dashboard fetches OS data via mTLS"
    echo ""
}

# Main
main() {
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   Zero Trust Hub-and-Spoke Deployment v7.0                   ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    deploy_terraform
    generate_inventory
    wait_for_vms
    deploy_ansible
    verify_deployment
    show_results
}

main "$@"
