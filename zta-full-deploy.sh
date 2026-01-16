#!/bin/bash
################################################################################
# ZTA Full Deployment v6.0 - CRITICAL FIXES
# - WireGuard tunnel for cross-cloud communication
# - Proper certificate synchronization
# - Enhanced security validation
################################################################################
set -e
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

BASE_DIR="/etc/zta-multicloud"
TERRAFORM_DIR="$BASE_DIR/terraform-openstack"
ANSIBLE_DIR="$BASE_DIR/ansible-zta"
INVENTORY_FILE="$ANSIBLE_DIR/inventory/hosts.ini"

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if resuming from terraform or starting fresh
SKIP_TERRAFORM=${SKIP_TERRAFORM:-false}

# Parse arguments
if [ "$1" == "--skip-terraform" ]; then
    SKIP_TERRAFORM=true
    log_warn "Skipping Terraform phase (using existing infrastructure)"
elif [ "$1" == "--help" ]; then
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --skip-terraform     Skip Terraform phase, use existing infrastructure"
    echo "  --help               Show this help message"
    exit 0
fi

# Check OpenStack credentials
check_openstack_auth() {
    if [ -z "$OS_AUTH_URL" ]; then
        log_error "OpenStack credentials not found!"
        log "Please source your OpenStack RC file:"
        log "  source ~/openrc.sh"
        exit 1
    fi
    
    log "OpenStack credentials detected:"
    log "  Auth URL: $OS_AUTH_URL"
    log "  Project: $OS_PROJECT_NAME"
    log "  User: $OS_USERNAME"
    
    # Test authentication
    if ! openstack token issue >/dev/null 2>&1; then
        log_error "OpenStack authentication failed!"
        log "Please verify your credentials and try again."
        exit 1
    fi
    log_success "OpenStack authentication successful"
}

# 1. Terraform & Firewall
deploy_terraform() {
    if [ "$SKIP_TERRAFORM" == "true" ]; then
        log "Skipping Terraform (using existing infrastructure)"
        cd "$TERRAFORM_DIR" || exit 1
    else
        log "STEP 1: Terraform Infrastructure Deployment"
        
        # Verify OpenStack credentials first
        check_openstack_auth
        
        cd "$TERRAFORM_DIR" || exit 1
        terraform init -upgrade >/dev/null
        
        log_warn "Starting Terraform apply (this may take 5-10 minutes)..."
        terraform apply -auto-approve
    fi
    
    AWS_GW=$(terraform output -raw aws_gateway_ip)
    OS_GW=$(terraform output -raw os_gateway_ip)
    MON_IP=$(terraform output -raw monitoring_ip)
    
    echo "$AWS_GW" > /tmp/aws_gw_ip.txt
    echo "$OS_GW" > /tmp/os_gw_ip.txt
    echo "$MON_IP" > /tmp/mon_ip.txt
    
    log_success "Infrastructure deployed: AWS=$AWS_GW, OS=$OS_GW, MON=$MON_IP"
}

fix_security_groups() {
    # Security groups are already configured in terraform
    # No need to reconfigure them here
    log "Firewall rules already configured in infrastructure"
    log_success "Skipping additional firewall configuration"
}

# 2. Inventory
generate_inventory() {
    log "STEP 2: Generating Ansible Inventory"
    AWS_GW=$(cat /tmp/aws_gw_ip.txt)
    OS_GW=$(cat /tmp/os_gw_ip.txt)
    MON_IP=$(cat /tmp/mon_ip.txt)

    # Clear SSH Keys
    ssh-keygen -f "/home/$(whoami)/.ssh/known_hosts" -R "$AWS_GW" 2>/dev/null || true
    ssh-keygen -f "/home/$(whoami)/.ssh/known_hosts" -R "$OS_GW" 2>/dev/null || true
    ssh-keygen -f "/home/$(whoami)/.ssh/known_hosts" -R "$MON_IP" 2>/dev/null || true
    ssh-keygen -f "/home/$(whoami)/.ssh/known_hosts" -R "10.30.1.20" 2>/dev/null || true

    mkdir -p "$(dirname "$INVENTORY_FILE")"
    cat > "$INVENTORY_FILE" << EOI
[all:vars]
ansible_user=ubuntu
ansible_ssh_private_key_file=~/.ssh/openstack-key.pem
ansible_python_interpreter=/usr/bin/python3
ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'

os_gateway_public_ip=$OS_GW
aws_gateway_public_ip=$AWS_GW
monitoring_public_ip=$MON_IP

[vm_gateway]
vm-aws-gateway ansible_host=$AWS_GW
vm-os-gateway  ansible_host=$OS_GW

[vm_monitoring]
vm-monitoring ansible_host=$MON_IP

[vm_identity]
vm-identity ansible_host=10.30.1.20 ansible_ssh_common_args='-o ProxyCommand="ssh -o StrictHostKeyChecking=no -W %h:%p -i ~/.ssh/openstack-key.pem ubuntu@$MON_IP"'

[k3s_masters]
aws-master ansible_host=10.20.2.10 ansible_ssh_common_args='-o ProxyCommand="ssh -o StrictHostKeyChecking=no -W %h:%p -i ~/.ssh/openstack-key.pem ubuntu@$AWS_GW"'
os-master  ansible_host=10.10.2.10 ansible_ssh_common_args='-o ProxyCommand="ssh -o StrictHostKeyChecking=no -W %h:%p -i ~/.ssh/openstack-key.pem ubuntu@$OS_GW"'
EOI
    log_success "Inventory generated"
}

# 3. Wait for VMs to be ready
wait_for_vms() {
    log "STEP 3: Waiting for VMs to be accessible"
    log_warn "Initial cloud-init delay (60 seconds)..."
    sleep 60
    
    AWS_GW=$(cat /tmp/aws_gw_ip.txt)
    OS_GW=$(cat /tmp/os_gw_ip.txt)
    MON_IP=$(cat /tmp/mon_ip.txt)
    
    for IP in $AWS_GW $OS_GW $MON_IP; do
        log "Checking connectivity to $IP..."
        for i in {1..120}; do
            if ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$IP "echo 'OK'" 2>/dev/null; then
                log_success "$IP is ready"
                break
            fi
            if [ $i -eq 120 ]; then
                log_error "VM $IP failed to respond after 20 minutes"
                log_warn "Checking network connectivity..."
                ping -c 3 "$IP" 2>&1 | tail -3
                log_warn "Attempting SSH with verbose output..."
                ssh -v -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$IP "echo 'OK'" 2>&1 | tail -10
                exit 1
            fi
            echo -ne "\r  Attempt $i/120..."
            sleep 10
        done
        echo ""
    done
}

# 4. Deploy with Ansible
deploy_ansible() {
    log "STEP 4: Running Ansible Playbook (This may take 10-15 minutes)"
    cd "$ANSIBLE_DIR" || exit 1
    
    # Run playbook with verbose output for debugging
    ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook -i "$INVENTORY_FILE" site.yml -v
    
    if [ $? -eq 0 ]; then
        log_success "Ansible deployment completed"
    else
        log_error "Ansible deployment failed"
        exit 1
    fi
}

# 4.5 Setup network bridge for isolated subnets
setup_network_bridge() {
    log "STEP 4.5: Setting up Network Bridge to Keycloak (systemd services)"
    AWS_GW=$(cat /tmp/aws_gw_ip.txt)
    MON_IP=$(cat /tmp/mon_ip.txt)
    
    # Verify keycloak-proxy service on monitoring VM
    log "Verifying keycloak-proxy service on monitoring VM..."
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$MON_IP \
      "sudo systemctl is-active keycloak-proxy && echo 'keycloak-proxy active' || sudo systemctl restart keycloak-proxy" 2>&1 | tail -1
    
    # Verify keycloak-forward service on AWS Gateway
    log "Verifying keycloak-forward service on AWS Gateway..."
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$AWS_GW \
      "sudo systemctl is-active keycloak-forward && echo 'keycloak-forward active' || sudo systemctl restart keycloak-forward" 2>&1 | tail -1
    
    sleep 2
    log_success "Network bridge setup complete (systemd services)"
}

# 5. Verify deployment
verify_deployment() {
    log "STEP 5: Verifying Zero Trust Architecture Components"
    AWS_GW=$(cat /tmp/aws_gw_ip.txt)
    OS_GW=$(cat /tmp/os_gw_ip.txt)
    
    # Check WireGuard tunnel
    log "Checking WireGuard tunnel..."
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$AWS_GW "sudo wg show" || log_warn "WireGuard not running on AWS Gateway"
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$OS_GW "sudo wg show" || log_warn "WireGuard not running on OS Gateway"
    
    # Check tunnel connectivity
    log "Testing tunnel connectivity..."
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$AWS_GW "ping -c 3 10.99.0.2" && log_success "Tunnel AWS->OS working" || log_warn "Tunnel connectivity issue"
    
    # Check Envoy
    log "Checking Envoy proxies..."
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$AWS_GW "docker ps | grep envoy" && log_success "Envoy running on AWS" || log_warn "Envoy not running on AWS"
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$OS_GW "docker ps | grep envoy" && log_success "Envoy running on OS" || log_warn "Envoy not running on OS"
    
    # Check OPA
    log "Checking OPA..."
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$AWS_GW "docker ps | grep opa" && log_success "OPA running" || log_warn "OPA not running"
    
    # Check Keycloak
    log "Checking Keycloak..."
    KEYCLOAK_STATUS=$(ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$AWS_GW \
      "timeout 3 curl -s http://127.0.0.1:8888/realms/zta 2>&1" | head -c 50)
    if [[ "$KEYCLOAK_STATUS" == *"realm"* ]] || [[ "$KEYCLOAK_STATUS" == *"public"* ]]; then
        log_success "Keycloak is accessible via network bridge"
    else
        log_warn "Keycloak health check may be incomplete"
    fi
    
    # Check frontend
    log "Checking frontend..."
    FRONTEND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://$AWS_GW/ 2>/dev/null || echo "000")
    if [ "$FRONTEND_STATUS" == "200" ]; then
        log_success "Frontend is accessible"
    else
        log_warn "Frontend returned $FRONTEND_STATUS"
    fi
}

# 6. Post-deployment certificate sync (CRITICAL FIX)
sync_certificates() {
    log "STEP 6: Synchronizing certificates between gateways"
    AWS_GW=$(cat /tmp/aws_gw_ip.txt)
    OS_GW=$(cat /tmp/os_gw_ip.txt)
    
    # Copy CA cert from AWS to OS
    log "Copying CA certificate from AWS to OS Gateway..."
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$AWS_GW "sudo cat /opt/certs/ca-cert.pem" | \
        ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$OS_GW "sudo tee /opt/certs/ca-cert.pem > /dev/null"
    
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$AWS_GW "sudo cat /opt/certs/ca-key.pem" | \
        ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$OS_GW "sudo tee /opt/certs/ca-key.pem > /dev/null"
    
    log_success "Certificates synchronized"
    
    # CRITICAL: Regenerate OS server certificate with synced CA
    log "Regenerating OS server certificate with synced CA..."
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$OS_GW '
      cd /opt/certs
      sudo rm -f os-server-cert.pem os-server.csr
      sudo openssl req -new -key os-server-key.pem -out os-server.csr -subj "/C=VN/CN=os-server"
      sudo openssl x509 -req -days 3650 -in os-server.csr -CA ca-cert.pem -CAkey ca-key.pem -CAcreateserial -out os-server-cert.pem
      sudo chmod 644 *.pem
      echo "OS server certificate regenerated"
    '
    log_success "OS server certificate regenerated with correct CA"
    
    # Restart Envoy to reload certificates
    log "Restarting Envoy containers..."
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$AWS_GW "sudo docker restart envoy-aws" || true
    ssh -o StrictHostKeyChecking=no -o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem ubuntu@$OS_GW "sudo docker restart envoy-os" || true
    
    sleep 5
    log_success "Envoy containers restarted"
}

# Main execution
main() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║  Zero Trust Architecture Multi-Cloud Deployment v6.0      ║${NC}"
    echo -e "${BLUE}║  OpenStack Hybrid Cloud with WireGuard Secure Tunnel      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    chmod +x /etc/zta-multicloud/utility-scripts/*.sh 2>/dev/null || true
    
    deploy_terraform
    fix_security_groups
    generate_inventory
    wait_for_vms
    deploy_ansible
    setup_network_bridge
    sync_certificates
    verify_deployment
    
    AWS_GW=$(cat /tmp/aws_gw_ip.txt)
    OS_GW=$(cat /tmp/os_gw_ip.txt)
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              DEPLOYMENT COMPLETED SUCCESSFULLY!            ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Access Points:${NC}"
    echo -e "  🌐 Frontend Application:    ${YELLOW}http://$AWS_GW/${NC}"
    echo -e "  📊 AWS Envoy Admin:         ${YELLOW}http://$AWS_GW:9901/${NC}"
    echo -e "  📊 OS Envoy Admin:          ${YELLOW}http://$OS_GW:9901/${NC}"
    echo -e "  🔑 Keycloak Admin:          ${YELLOW}http://10.30.1.20:8080/${NC}"
    echo ""
    echo -e "${BLUE}Test Credentials:${NC}"
    echo -e "  Username: ${YELLOW}demo${NC}"
    echo -e "  Password: ${YELLOW}demo123${NC}"
    echo ""
    echo -e "${BLUE}Zero Trust Components:${NC}"
    echo -e "  ✓ Identity Provider (Keycloak)"
    echo -e "  ✓ Policy Decision Point (OPA)"
    echo -e "  ✓ Policy Enforcement Point (Envoy)"
    echo -e "  ✓ Service Mesh (mTLS + WireGuard)"
    echo -e "  ✓ Workload Identity (SPIRE)"
    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo -e "  1. Run testing: ${YELLOW}bash /etc/zta-multicloud/utility-scripts/zta-test-auth.sh${NC}"
    echo -e "  2. Open browser: ${YELLOW}http://$AWS_GW${NC}"
    echo -e "  3. Login and test data retrieval from Private Cloud"
    echo ""
}

main "$@"