#!/bin/bash
################################################################################
# ZTA Cleanup Script - Remove old deployment
################################################################################
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

echo "╔════════════════════════════════════════════════════════════╗"
echo "║        ZTA Multi-Cloud Cleanup Script                      ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if we should proceed
log_warn "This will DELETE all ZTA resources in project: ZeroTrust_Project"
log_warn "Including: VMs, Networks, Routers, Floating IPs, Security Groups"
echo ""
read -p "Are you sure you want to continue? (yes/no): " confirm

if [ "$confirm" != "yes" ]; then
    log "Cleanup cancelled"
    exit 0
fi

echo ""
log "Starting cleanup..."

# 1. Delete instances
log "Deleting instances..."
for instance in $(openstack server list --project ZeroTrust_Project -f value -c ID); do
    name=$(openstack server show $instance -f value -c name)
    log "  Deleting instance: $name ($instance)"
    openstack server delete $instance || true
done

# Wait for instances to be deleted
log "Waiting for instances to be deleted..."
sleep 10

# 2. Delete floating IPs
log "Deleting floating IPs..."
for fip in $(openstack floating ip list --project ZeroTrust_Project -f value -c ID 2>/dev/null || true); do
    ip=$(openstack floating ip show $fip -f value -c floating_ip_address 2>/dev/null || echo "unknown")
    log "  Deleting floating IP: $ip ($fip)"
    openstack floating ip delete $fip || true
done

# 3. Delete router interfaces and routers
log "Deleting routers..."
for router in $(openstack router list --project ZeroTrust_Project -f value -c ID); do
    rname=$(openstack router show $router -f value -c name)
    log "  Processing router: $rname"
    
    # Remove interfaces
    for port in $(openstack router show $router -f json | jq -r '.interfaces_info[].port_id' 2>/dev/null || true); do
        log "    Removing interface: $port"
        openstack router remove port $router $port 2>/dev/null || true
    done
    
    # Remove gateway
    log "    Clearing gateway"
    openstack router unset --external-gateway $router 2>/dev/null || true
    
    # Delete router
    log "    Deleting router"
    openstack router delete $router || true
done

sleep 5

# 4. Delete ports
log "Deleting ports..."
for port in $(openstack port list --project ZeroTrust_Project -f value -c ID); do
    log "  Deleting port: $port"
    openstack port delete $port 2>/dev/null || true
done

# 5. Delete networks and subnets
log "Deleting networks..."
for net in $(openstack network list --project ZeroTrust_Project -f value -c ID); do
    nname=$(openstack network show $net -f value -c name)
    log "  Deleting network: $nname"
    
    # Delete subnets first
    for subnet in $(openstack subnet list --network $net -f value -c ID); do
        log "    Deleting subnet: $subnet"
        openstack subnet delete $subnet 2>/dev/null || true
    done
    
    # Delete network
    openstack network delete $net 2>/dev/null || true
done

# 6. Delete security groups (except default)
log "Deleting security groups..."
for sg in $(openstack security group list --project ZeroTrust_Project -f value -c ID); do
    sgname=$(openstack security group show $sg -f value -c name)
    if [ "$sgname" != "default" ]; then
        log "  Deleting security group: $sgname"
        openstack security group delete $sg || true
    fi
done

# 7. Delete keypairs
log "Deleting keypairs..."
for keypair in $(openstack keypair list --project ZeroTrust_Project -f value -c Name); do
    if [[ "$keypair" == "zta-"* ]]; then
        log "  Deleting keypair: $keypair"
        openstack keypair delete $keypair || true
    fi
done

echo ""
log_success "Cleanup completed!"
log "You can now run './zta-full-deploy.sh' to deploy fresh infrastructure"
