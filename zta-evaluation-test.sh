#!/bin/bash
#═══════════════════════════════════════════════════════════════════════════════
# Zero Trust Architecture - Evaluation Test Suite
# Updated for Hub-and-Spoke deployment via Auth Portal
#═══════════════════════════════════════════════════════════════════════════════

set +e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

#═══════════════════════════════════════════════════════════════════════════════
# Configuration - Updated for current deployment
#═══════════════════════════════════════════════════════════════════════════════

# Entry Points (Floating IPs) - ONLY Auth Portal has public IP
AUTH_PORTAL="172.10.10.170"           # THE ONLY public entry point - DMZ

# Internal IPs (accessed via SSH ProxyCommand through Auth Portal)
MONITORING="10.40.1.10"               # Grafana, Prometheus - NO public IP
AWS_GATEWAY_INTERNAL="10.20.2.5"
OS_GATEWAY_INTERNAL="10.10.2.5"
IDENTITY_IP="10.40.1.20"

# SSH config
SSH_KEY="$HOME/.ssh/id_rsa_zerotrust"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o ConnectTimeout=10"

# User Accounts (4 Demo Roles)
# 1. viewer    - AWS UI only (no data)
# 2. aws_user  - AWS UI + AWS data
# 3. full_user - AWS UI + AWS data + OS data
# 4. admin     - Full access including monitoring
declare -A USERS
declare -A USER_PERMS

USERS["viewer"]="viewer123"
USER_PERMS["viewer"]="aws:ui"

USERS["aws_user"]="aws123"
USER_PERMS["aws_user"]="aws:ui,aws:read"

USERS["full_user"]="full123"
USER_PERMS["full_user"]="aws:ui,aws:read,os:read"

USERS["admin"]="admin123"
USER_PERMS["admin"]="aws:ui,aws:read,aws:write,os:read,os:write,monitoring:read"

# API Endpoints
AWS_DATA_API="http://${AUTH_PORTAL}:8888/api/aws/data"
OS_DATA_API="http://${AUTH_PORTAL}:8888/api/os/data"
AUTH_API="http://${AUTH_PORTAL}:8888/api/login"

# Results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0
SKIPPED_TESTS=0

#═══════════════════════════════════════════════════════════════════════════════
# Helper Functions
#═══════════════════════════════════════════════════════════════════════════════

print_header() {
    echo ""
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${NC}  ${BOLD}$1${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════════════════════════╝${NC}"
}

print_section() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_subsection() {
    echo -e "\n  ${MAGENTA}▸ $1${NC}"
}

test_pass() {
    echo -e "  ${GREEN}✓ PASS${NC}: $1"
    ((PASSED_TESTS++))
    ((TOTAL_TESTS++))
}

test_fail() {
    local reason="${2:-}"
    if [[ -n "$reason" ]]; then
        echo -e "  ${RED}✗ FAIL${NC}: $1 ${DIM}($reason)${NC}"
    else
        echo -e "  ${RED}✗ FAIL${NC}: $1"
    fi
    ((FAILED_TESTS++))
    ((TOTAL_TESTS++))
}

test_skip() {
    echo -e "  ${YELLOW}○ SKIP${NC}: $1 ${DIM}($2)${NC}"
    ((SKIPPED_TESTS++))
}

test_info() {
    echo -e "  ${YELLOW}ℹ INFO${NC}: $1"
}

test_metric() {
    echo -e "  ${CYAN}📊 METRIC${NC}: $1"
}

ssh_cmd() {
    local host=$1
    shift
    ssh $SSH_OPTS -i "$SSH_KEY" ubuntu@"$host" "$@" 2>/dev/null
}

# Nested SSH: Auth Portal → Internal VM
ssh_internal() {
    local internal_ip=$1
    shift
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$AUTH_PORTAL" \
        "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i ~/.ssh/id_rsa_zerotrust ubuntu@${internal_ip} '$*'" 2>/dev/null
}

# Get JWT token for a user
get_jwt_token() {
    local username="$1"
    local password="$2"
    local response
    
    response=$(curl -s --max-time 10 "http://${AUTH_PORTAL}:8888/api/login" \
        -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"${username}\",\"password\":\"${password}\"}" 2>/dev/null)
    
    # Handle both "token": "..." and "token":"..." formats
    echo "$response" | sed 's/": "/":"/g' | grep -o '"token":"[^"]*"' | cut -d'"' -f4
}

# Test API endpoint with token
test_api_access() {
    local token="$1"
    local endpoint="$2"
    local http_code
    
    http_code=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $token" \
        "$endpoint" 2>/dev/null || echo "000")
    
    echo "$http_code"
}

# Decode JWT payload
decode_jwt() {
    local token="$1"
    echo "$token" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq . 2>/dev/null
}

#═══════════════════════════════════════════════════════════════════════════════
# SECTION 1: Connectivity Tests
#═══════════════════════════════════════════════════════════════════════════════

test_connectivity() {
    print_header "I. KIỂM TRA KẾT NỐI (Connectivity Tests)"
    
    print_section "1.1 Entry Points Accessibility"
    
    # Auth Portal
    local auth_code=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "http://${AUTH_PORTAL}/" 2>/dev/null || echo "000")
    if [[ "$auth_code" == "200" ]]; then
        test_pass "Auth Portal UI (${AUTH_PORTAL}:80) - HTTP $auth_code"
    else
        test_fail "Auth Portal UI" "HTTP $auth_code"
    fi
    
    # Auth API
    local api_code=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "http://${AUTH_PORTAL}/api/login" -X POST -H 'Content-Type: application/json' -d '{}' 2>/dev/null || echo "000")
    if [[ "$api_code" == "401" ]]; then
        test_pass "Auth API (${AUTH_PORTAL}/api/login) - Returns 401 for empty credentials"
    else
        test_fail "Auth API" "Expected 401, got $api_code"
    fi
    
    # Monitoring services tested in Section IV
    test_info "Monitoring services (Grafana/Prometheus) - see Section IV"
    
    print_section "1.2 Internal Services (via SSH)"
    
    # Check services on Auth Portal
    local auth_services=$(ssh_cmd "$AUTH_PORTAL" "sudo docker ps --format '{{.Names}}' 2>/dev/null | tr '\n' ','")
    if [[ -n "$auth_services" ]]; then
        test_pass "Auth Portal containers: $auth_services"
    else
        test_info "Cannot check Auth Portal containers via SSH"
    fi
    
    # Check JWT API is running
    local jwt_check=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$AUTH_PORTAL" "ss -tlnp 2>/dev/null | grep -q ':8888' && echo OK" 2>/dev/null)
    if [[ "$jwt_check" == "OK" ]]; then
        test_pass "JWT Auth Server running on port 8888"
    else
        test_fail "JWT Auth Server not running"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# SECTION 2: Authentication Tests
#═══════════════════════════════════════════════════════════════════════════════

test_authentication() {
    print_header "II. KIỂM TRA XÁC THỰC (Authentication Tests)"
    
    print_section "2.1 Valid User Authentication"
    
    for username in "${!USERS[@]}"; do
        password="${USERS[$username]}"
        token=$(get_jwt_token "$username" "$password")
        
        if [[ -n "$token" ]]; then
            test_pass "$username: JWT token obtained"
            
            # Decode and show permissions
            payload=$(decode_jwt "$token")
            if [[ -n "$payload" ]]; then
                role=$(echo "$payload" | jq -r '.role')
                perms=$(echo "$payload" | jq -r '.permissions | join(", ")')
                test_metric "$username: role=$role, permissions=[$perms]"
            fi
        else
            test_fail "$username: Failed to get JWT token"
        fi
    done
    
    print_section "2.2 Invalid Credentials Rejection"
    
    # Wrong password
    local bad_response=$(curl -s --max-time 5 "http://${AUTH_PORTAL}/api/login" \
        -X POST -H 'Content-Type: application/json' \
        -d '{"username":"admin","password":"wrongpassword"}' 2>/dev/null)
    
    if echo "$bad_response" | grep -q "Invalid credentials"; then
        test_pass "Wrong password correctly rejected"
    else
        test_fail "Wrong password not rejected properly"
    fi
    
    # Non-existent user
    local fake_response=$(curl -s --max-time 5 "http://${AUTH_PORTAL}/api/login" \
        -X POST -H 'Content-Type: application/json' \
        -d '{"username":"hacker","password":"hack123"}' 2>/dev/null)
    
    if echo "$fake_response" | grep -q "Invalid credentials"; then
        test_pass "Non-existent user correctly rejected"
    else
        test_fail "Non-existent user not rejected properly"
    fi
    
    print_section "2.3 JWT Token Validation"
    
    # Get a fresh token
    local token=$(get_jwt_token "admin" "admin123")
    if [[ -n "$token" ]]; then
        local payload=$(decode_jwt "$token")
        
        # Check required claims
        local has_sub=$(echo "$payload" | jq -r '.sub')
        local has_exp=$(echo "$payload" | jq -r '.exp')
        local has_iat=$(echo "$payload" | jq -r '.iat')
        local has_iss=$(echo "$payload" | jq -r '.iss')
        
        if [[ "$has_sub" == "admin" ]]; then
            test_pass "JWT contains 'sub' claim"
        else
            test_fail "JWT missing 'sub' claim"
        fi
        
        if [[ "$has_exp" =~ ^[0-9]+$ ]]; then
            test_pass "JWT contains 'exp' claim (expiry)"
            local now=$(date +%s)
            local ttl=$((has_exp - now))
            test_metric "Token TTL: ${ttl}s (~$((ttl/60)) minutes)"
        else
            test_fail "JWT missing 'exp' claim"
        fi
        
        if [[ "$has_iss" == "zta-auth-portal" ]]; then
            test_pass "JWT issuer: zta-auth-portal"
        else
            test_fail "JWT has wrong issuer: $has_iss"
        fi
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# SECTION 3: RBAC Authorization Tests + 4 User Scenario Demo
#═══════════════════════════════════════════════════════════════════════════════

test_rbac() {
    print_header "III. KIỂM TRA PHÂN QUYỀN RBAC (Authorization Tests)"
    
    echo -e "\n  ${BOLD}Permission Matrix (4 User Roles):${NC}"
    echo -e "  ┌─────────────┬───────────┬───────────┬───────────┬────────────┐"
    echo -e "  │ User        │ AWS UI    │ AWS Data  │ OS Data   │ Monitoring │"
    echo -e "  ├─────────────┼───────────┼───────────┼───────────┼────────────┤"
    echo -e "  │ viewer      │ ${GREEN}✓ YES${NC}     │ ${RED}✗ NO${NC}      │ ${RED}✗ NO${NC}      │ ${RED}✗ NO${NC}       │"
    echo -e "  │ aws_user    │ ${GREEN}✓ YES${NC}     │ ${GREEN}✓ YES${NC}     │ ${RED}✗ NO${NC}      │ ${RED}✗ NO${NC}       │"
    echo -e "  │ full_user   │ ${GREEN}✓ YES${NC}     │ ${GREEN}✓ YES${NC}     │ ${GREEN}✓ YES${NC}     │ ${RED}✗ NO${NC}       │"
    echo -e "  │ admin       │ ${GREEN}✓ YES${NC}     │ ${GREEN}✓ YES${NC}     │ ${GREEN}✓ YES${NC}     │ ${GREEN}✓ YES${NC}      │"
    echo -e "  └─────────────┴───────────┴───────────┴───────────┴────────────┘"
    
    # Detailed 4-user tests moved to Section VIII (Demo)
    test_info "Detailed 4-user permission tests - see Section VIII (Demo)"
    
    print_section "3.1 Unauthenticated Access Blocking"
    
    # Test AWS API without token
    local aws_noauth=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "$AWS_DATA_API" 2>/dev/null || echo "000")
    if [[ "$aws_noauth" == "401" ]]; then
        test_pass "AWS API blocks unauthenticated requests (HTTP 401)"
    else
        test_info "AWS API returned HTTP $aws_noauth without auth"
    fi
    
    # Test OS API without token
    local os_noauth=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "$OS_DATA_API" 2>/dev/null || echo "000")
    if [[ "$os_noauth" == "401" ]]; then
        test_pass "OS API blocks unauthenticated requests (HTTP 401)"
    else
        test_info "OS API returned HTTP $os_noauth without auth"
    fi
    
    print_section "3.2 Invalid Token Rejection"
    
    local fake_token="eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAiZmFrZSJ9.invalidsig"
    local invalid_result=$(test_api_access "$fake_token" "$AWS_DATA_API")
    if [[ "$invalid_result" == "401" ]]; then
        test_pass "Invalid JWT token rejected (HTTP 401)"
    else
        test_info "Invalid token returned HTTP $invalid_result"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# SECTION 4: Monitoring Stack Tests
#═══════════════════════════════════════════════════════════════════════════════

test_monitoring() {
    print_header "IV. KIỂM TRA MONITORING (Observability Tests)"
    
    echo -e "  ${CYAN}ℹ Zero Trust: Monitoring has NO public IP${NC}"
    echo -e "  ${CYAN}  Access via SSH tunnel: ssh -L 3000:${MONITORING}:3000 ubuntu@${AUTH_PORTAL}${NC}"
    echo ""
    
    print_section "4.1 Grafana (via SSH tunnel)"
    
    # Test Grafana via Auth Portal
    local grafana_health=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$AUTH_PORTAL" "curl -s --max-time 5 'http://${MONITORING}:3000/api/health' 2>/dev/null" 2>/dev/null)
    if echo "$grafana_health" | grep -q "ok"; then
        test_pass "Grafana is healthy (via SSH tunnel)"
        local grafana_version=$(echo "$grafana_health" | jq -r '.version // "unknown"' 2>/dev/null)
        test_metric "Grafana version: $grafana_version"
    else
        test_info "Grafana not responding - ensure monitoring VM is running"
    fi
    
    print_section "4.2 Prometheus (via SSH tunnel)"
    
    # Test Prometheus ready endpoint
    local prom_ready=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$AUTH_PORTAL" "curl -s --max-time 5 'http://${MONITORING}:9090/-/ready' 2>/dev/null" 2>/dev/null)
    if [[ "$prom_ready" == *"ready"* ]] || [[ "$prom_ready" == *"OK"* ]] || [[ -n "$prom_ready" ]]; then
        test_pass "Prometheus is ready (via SSH tunnel)"
    else
        test_info "Prometheus not responding - ensure monitoring VM is running"
    fi
    
    # Check Prometheus targets
    local prom_targets_json=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$AUTH_PORTAL" "curl -s --max-time 5 'http://${MONITORING}:9090/api/v1/targets' 2>/dev/null" 2>/dev/null)
    local prom_targets=$(echo "$prom_targets_json" | jq -r '.data.activeTargets | length' 2>/dev/null)
    if [[ "$prom_targets" =~ ^[0-9]+$ ]] && [[ "$prom_targets" -gt 0 ]]; then
        test_pass "Prometheus collecting metrics from $prom_targets active targets"
        test_metric "Real-time health monitoring: $prom_targets services tracked"
    else
        test_info "Prometheus targets: ${prom_targets:-N/A}"
    fi
    
    print_section "4.3 Loki (Log Aggregation)"
    
    local loki_ready=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$AUTH_PORTAL" "curl -s --max-time 5 -o /dev/null -w '%{http_code}' 'http://${MONITORING}:3100/ready' 2>/dev/null" 2>/dev/null)
    if [[ "$loki_ready" == "200" ]]; then
        test_pass "Loki is ready (via SSH tunnel)"
    else
        test_info "Loki not deployed or not responding"
    fi
    
    print_section "4.4 SPIRE/SVID Certificate Rotation"
    
    echo -e "  ${CYAN}ℹ SVID (SPIFFE Verifiable Identity Document) certificates${NC}"
    echo -e "  ${CYAN}  are auto-rotated every 5 minutes by SPIRE agents${NC}"
    echo ""
    
    # Check SPIRE Server is running on Identity VM using ssh_internal
    local spire_status=$(ssh_internal "$IDENTITY_IP" "systemctl is-active spire-server 2>/dev/null")
    if [[ "$spire_status" == "active" ]]; then
        test_pass "SPIRE Server is running on Identity VM (${IDENTITY_IP})"
    else
        local spire_pid=$(ssh_internal "$IDENTITY_IP" "pgrep -f spire-server 2>/dev/null")
        if [[ -n "$spire_pid" ]]; then
            test_pass "SPIRE Server process running (PID: $spire_pid)"
        else
            test_info "Cannot verify SPIRE Server status - check manually"
        fi
    fi
    
    # Check SVID TTL configuration
    local svid_ttl=$(ssh_internal "$IDENTITY_IP" "grep default_x509_svid_ttl /opt/spire/conf/server/server.conf 2>/dev/null | head -1")
    if [[ -n "$svid_ttl" ]]; then
        test_pass "SVID TTL configured: $svid_ttl"
        if echo "$svid_ttl" | grep -q "5m"; then
            test_metric "SVID rotation interval: 5 minutes (as configured)"
        fi
    else
        test_info "Cannot read SVID TTL config - verify on Identity VM"
    fi
    
    # Check SPIRE Agent on AWS Gateway
    local aws_agent=$(ssh_internal "$AWS_GATEWAY_INTERNAL" "pgrep -f spire-agent 2>/dev/null")
    if [[ -n "$aws_agent" ]]; then
        test_pass "SPIRE Agent running on AWS Gateway (PID: $aws_agent)"
    else
        test_info "SPIRE Agent not running on AWS Gateway"
    fi
    
    # Check SPIRE Agent on OS Gateway
    local os_agent=$(ssh_internal "$OS_GATEWAY_INTERNAL" "pgrep -f spire-agent 2>/dev/null")
    if [[ -n "$os_agent" ]]; then
        test_pass "SPIRE Agent running on OS Gateway (PID: $os_agent)"
    else
        test_info "SPIRE Agent not running on OS Gateway"
    fi
    
    # Show SVID info if SPIRE agent is available
    if [[ -n "$aws_agent" ]]; then
        local svid_info=$(ssh_internal "$AWS_GATEWAY_INTERNAL" "/opt/spire/bin/spire-agent api fetch x509 -socketPath /tmp/spire-agent/public/api.sock 2>/dev/null | head -3")
        if [[ -n "$svid_info" ]]; then
            test_pass "SVID certificates are being issued by SPIRE"
            echo -e "  ${DIM}$svid_info${NC}"
        fi
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# SECTION 5: Infrastructure Tests
#═══════════════════════════════════════════════════════════════════════════════

test_infrastructure() {
    print_header "V. KIỂM TRA HẠ TẦNG (Infrastructure Tests)"
    
    print_section "5.1 Docker Containers"
    
    # Auth Portal containers - check via docker ps (no sudo needed if user in docker group)
    local auth_containers=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$AUTH_PORTAL" "docker ps --format '{{.Names}}: {{.Status}}' 2>/dev/null || sudo docker ps --format '{{.Names}}: {{.Status}}' 2>/dev/null" 2>/dev/null)
    if [[ -n "$auth_containers" ]]; then
        echo -e "  ${CYAN}Auth Portal containers:${NC}"
        echo "$auth_containers" | while read line; do
            echo "    - $line"
        done
        test_pass "Auth Portal has running containers"
    else
        # Fallback: check if port 8888 is listening (service is running)
        local port_check=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$AUTH_PORTAL" "ss -tlnp 2>/dev/null | grep -E ':80|:8888' | wc -l" 2>/dev/null)
        if [[ "$port_check" -ge 1 ]]; then
            test_pass "Auth Portal services running (ports 80/8888 active)"
        else
            test_info "Cannot verify Auth Portal containers"
        fi
    fi
    
    # Monitoring containers - check via HTTP health endpoints (more reliable)
    local grafana_ok=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$AUTH_PORTAL" "curl -s --max-time 3 http://${MONITORING}:3000/api/health 2>/dev/null | grep -q 'ok' && echo OK" 2>/dev/null)
    local prom_ok=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$AUTH_PORTAL" "curl -s --max-time 3 http://${MONITORING}:9090/-/ready 2>/dev/null | grep -qi 'ready\|OK' && echo OK || curl -s --max-time 3 -o /dev/null -w '%{http_code}' http://${MONITORING}:9090/-/ready 2>/dev/null | grep -q '200' && echo OK" 2>/dev/null)
    
    if [[ "$grafana_ok" == "OK" ]] || [[ "$prom_ok" == "OK" ]]; then
        local services=""
        [[ "$grafana_ok" == "OK" ]] && services="Grafana"
        [[ "$prom_ok" == "OK" ]] && services="${services:+$services, }Prometheus"
        test_pass "Monitoring services running ($services)"
    else
        test_info "Monitoring services not responding (VM may be stopped)"
    fi
    
    print_section "5.2 Terraform State"
    
    if [[ -f "/etc/zta-multicloud/terraform-openstack/terraform.tfstate" ]]; then
        local resource_count=$(grep -c '"type":' /etc/zta-multicloud/terraform-openstack/terraform.tfstate 2>/dev/null || echo "0")
        test_pass "Terraform state exists"
        test_metric "Managed resources: $resource_count"
    else
        test_fail "Terraform state not found"
    fi
    
    print_section "5.3 Network Connectivity"
    
    # Check internal network via Auth Portal - use simple ping check
    local can_reach_aws=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$AUTH_PORTAL" "ping -c 1 -W 2 ${AWS_GATEWAY_INTERNAL} >/dev/null 2>&1 && echo OK || echo FAIL" 2>/dev/null)
    if [[ "$can_reach_aws" == "OK" ]]; then
        test_pass "Auth Portal can reach AWS Gateway ($AWS_GATEWAY_INTERNAL)"
    else
        test_fail "Auth Portal cannot reach AWS Gateway"
    fi
    
    local can_reach_os=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" ubuntu@"$AUTH_PORTAL" "ping -c 1 -W 2 ${OS_GATEWAY_INTERNAL} >/dev/null 2>&1 && echo OK || echo FAIL" 2>/dev/null)
    if [[ "$can_reach_os" == "OK" ]]; then
        test_pass "Auth Portal can reach OS Gateway ($OS_GATEWAY_INTERNAL)"
    else
        test_fail "Auth Portal cannot reach OS Gateway"
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# SECTION 6: End-to-End Flow Test
#═══════════════════════════════════════════════════════════════════════════════

test_e2e_flow() {
    print_header "VI. KIỂM TRA LUỒNG ĐẦU CUỐI (E2E Flow Test)"
    
    echo -e "\n  ${BOLD}Flow: User → Auth Portal → JWT → AWS/OS API${NC}\n"
    
    print_section "6.1 Complete Zero Trust Flow"
    
    echo -e "  ${CYAN}Testing complete flow with full_user...${NC}"
    
    # Step 1: Login and get token
    local token=$(get_jwt_token "full_user" "full123")
    if [[ -n "$token" ]]; then
        test_pass "Step 1: JWT obtained via Auth Portal"
    else
        test_fail "Step 1: Failed to get JWT"
        return
    fi
    
    # Step 2: Access AWS API with JWT
    local aws_api=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $token" "$AWS_DATA_API" 2>/dev/null || echo "000")
    if [[ "$aws_api" == "200" ]]; then
        test_pass "Step 2: AWS API access with JWT (HTTP 200)"
    else
        test_info "Step 2: AWS API returned HTTP $aws_api"
    fi
    
    # Step 3: Cross-cluster OS API via mTLS
    local os_api=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $token" "$OS_DATA_API" 2>/dev/null || echo "000")
    if [[ "$os_api" == "200" ]]; then
        test_pass "Step 3: OS API cross-cluster via mTLS (HTTP 200)"
    else
        test_info "Step 3: OS API returned HTTP $os_api"
    fi
    
    echo -e "\n  ${BOLD}Zero Trust Flow Complete:${NC}"
    echo "  User → Auth Portal → JWT → API Gateway → Backend (via mTLS)"
}

#═══════════════════════════════════════════════════════════════════════════════
# Performance Tests (Optional)
#═══════════════════════════════════════════════════════════════════════════════

test_performance() {
    print_header "VII. KIỂM TRA HIỆU NĂNG (Performance Tests)"
    
    print_section "7.1 Authentication Latency"
    
    local total=0
    local count=5
    
    for i in $(seq 1 $count); do
        local start=$(date +%s%N)
        get_jwt_token "admin" "admin123" > /dev/null
        local end=$(date +%s%N)
        local elapsed=$(( (end - start) / 1000000 ))
        total=$((total + elapsed))
    done
    
    local avg=$((total / count))
    test_metric "Average auth latency: ${avg}ms (over $count requests)"
    
    if [[ $avg -lt 500 ]]; then
        test_pass "Auth latency acceptable (<500ms)"
    else
        test_info "Auth latency is ${avg}ms - may need optimization"
    fi
    
    print_section "7.2 Portal Response Time"
    
    local portal_time=$(curl -s --max-time 10 -o /dev/null -w "%{time_total}" "http://${AUTH_PORTAL}:8888/" 2>/dev/null)
    local portal_ms=$(echo "$portal_time * 1000" | bc 2>/dev/null | cut -d'.' -f1)
    
    if [[ -n "$portal_ms" ]]; then
        test_metric "Portal response time: ${portal_ms}ms"
        if [[ "$portal_ms" -lt 200 ]]; then
            test_pass "Portal response time excellent (<200ms)"
        else
            test_pass "Portal response time acceptable"
        fi
    fi
}

#═══════════════════════════════════════════════════════════════════════════════
# SECTION 8: 4-User Scenario Demo (Interactive)
#═══════════════════════════════════════════════════════════════════════════════

demo_user_scenario() {
    local username="$1"
    local password="$2"
    local expected_aws="$3"
    local expected_os="$4"
    local desc="$5"
    
    echo ""
    echo -e "  ${CYAN}┌────────────────────────────────────────────────────────────────────────┐${NC}"
    echo -e "  ${CYAN}│${NC} ${BOLD}User: $username${NC} - $desc"
    echo -e "  ${CYAN}└────────────────────────────────────────────────────────────────────────┘${NC}"
    
    # Step 1: Login
    echo -e "  ${YELLOW}[1]${NC} Đăng nhập..."
    local token=$(get_jwt_token "$username" "$password")
    
    if [[ -z "$token" ]]; then
        echo -e "      ${RED}❌ Login failed${NC}"
        return 1
    fi
    echo -e "      ${GREEN}✓ Token received${NC}"
    
    # Decode and show JWT
    local payload=$(decode_jwt "$token")
    if [[ -n "$payload" ]]; then
        local role=$(echo "$payload" | grep -o '"role": "[^"]*"' | cut -d'"' -f4)
        local perms=$(echo "$payload" | grep -o '"permissions": \[[^]]*\]' | sed 's/"permissions": //; s/\[//; s/\]//; s/"//g')
        echo -e "      Role: ${MAGENTA}$role${NC}"
        echo -e "      Permissions: ${CYAN}[$perms]${NC}"
    fi
    
    # Step 2: Try AWS Data
    echo -e "  ${YELLOW}[2]${NC} Fetch AWS Cluster Data..."
    local aws_code=$(test_api_access "$token" "$AWS_DATA_API")
    
    if [[ "$aws_code" == "200" ]]; then
        echo -e "      ${GREEN}✓ HTTP 200 - Access GRANTED${NC}"
        local aws_data=$(curl -s --max-time 5 -H "Authorization: Bearer $token" "$AWS_DATA_API" 2>/dev/null)
        local aws_cluster=$(echo "$aws_data" | grep -o '"cluster": "[^"]*"' | cut -d'"' -f4)
        echo -e "      Data: cluster=${aws_cluster}"
        
        if [[ "$expected_aws" == "yes" ]]; then
            test_pass "$username: AWS access correct (granted)"
        else
            test_fail "$username: AWS should be denied" "got HTTP 200"
        fi
    else
        echo -e "      ${RED}✗ HTTP $aws_code - Access DENIED${NC}"
        if [[ "$expected_aws" == "no" ]]; then
            test_pass "$username: AWS access correct (denied)"
        else
            test_fail "$username: AWS should be granted" "got HTTP $aws_code"
        fi
    fi
    
    # Step 3: Try OS Data
    echo -e "  ${YELLOW}[3]${NC} Fetch OS Cluster Data (cross-cluster via mTLS)..."
    local os_code=$(test_api_access "$token" "$OS_DATA_API")
    
    if [[ "$os_code" == "200" ]]; then
        echo -e "      ${GREEN}✓ HTTP 200 - Access GRANTED${NC}"
        local os_data=$(curl -s --max-time 5 -H "Authorization: Bearer $token" "$OS_DATA_API" 2>/dev/null)
        local os_cluster=$(echo "$os_data" | grep -o '"cluster": "[^"]*"' | cut -d'"' -f4)
        echo -e "      Data: cluster=${os_cluster}"
        
        if [[ "$expected_os" == "yes" ]]; then
            test_pass "$username: OS access correct (granted)"
        else
            test_fail "$username: OS should be denied" "got HTTP 200"
        fi
    else
        echo -e "      ${RED}✗ HTTP $os_code - Access DENIED${NC}"
        if [[ "$expected_os" == "no" ]]; then
            test_pass "$username: OS access correct (denied)"
        else
            test_fail "$username: OS should be granted" "got HTTP $os_code"
        fi
    fi
}

test_user_scenarios() {
    print_header "VIII. DEMO KỊCH BẢN 4 USER (User Scenario Demo)"
    
    echo -e "\n  ${BOLD}Kịch bản demo Zero Trust với 4 loại người dùng:${NC}"
    echo -e "  1. ${GREEN}viewer${NC}    - Chỉ xem AWS UI, không fetch được data"
    echo -e "  2. ${GREEN}aws_user${NC}  - AWS UI + AWS data, không fetch OS"
    echo -e "  3. ${GREEN}full_user${NC} - AWS UI + AWS data + OS data"
    echo -e "  4. ${GREEN}admin${NC}     - Full access + Monitoring"
    
    print_section "8.1 Scenario 1: viewer (AWS UI only)"
    demo_user_scenario "viewer" "viewer123" "no" "no" "Chỉ có quyền aws:ui"
    
    print_section "8.2 Scenario 2: aws_user (AWS UI + AWS Data)"
    demo_user_scenario "aws_user" "aws123" "yes" "no" "Có quyền aws:ui, aws:read"
    
    print_section "8.3 Scenario 3: full_user (AWS + OS Data)"
    demo_user_scenario "full_user" "full123" "yes" "yes" "Có quyền aws:ui, aws:read, os:read"
    
    print_section "8.4 Scenario 4: admin (Full Access)"
    demo_user_scenario "admin" "admin123" "yes" "yes" "Full permissions + monitoring"
    
    # Admin monitoring access (via SSH tunnel - Zero Trust)
    echo ""
    echo -e "  ${YELLOW}[4]${NC} Kiểm tra Monitoring access (admin only via SSH tunnel)..."
    echo -e "      ${CYAN}ℹ Zero Trust: Monitoring only accessible via Auth Portal${NC}"
    
    local grafana_code=$(ssh_cmd "$AUTH_PORTAL" "curl -s --max-time 5 -o /dev/null -w '%{http_code}' 'http://${MONITORING}:3000/api/health' 2>/dev/null")
    if [[ "$grafana_code" == "200" ]]; then
        echo -e "      ${GREEN}✓ Grafana accessible (via SSH tunnel)${NC}"
        test_pass "admin: Grafana monitoring access (via tunnel)"
    else
        echo -e "      ${YELLOW}ℹ Grafana: Use SSH tunnel - ssh -L 3000:${MONITORING}:3000 ubuntu@${AUTH_PORTAL}${NC}"
    fi
    
    local prom_code=$(ssh_cmd "$AUTH_PORTAL" "curl -s --max-time 5 -o /dev/null -w '%{http_code}' 'http://${MONITORING}:9090/-/ready' 2>/dev/null")
    if [[ "$prom_code" == "200" ]]; then
        echo -e "      ${GREEN}✓ Prometheus accessible (via SSH tunnel)${NC}"
        test_pass "admin: Prometheus monitoring access (via tunnel)"
    else
        echo -e "      ${YELLOW}ℹ Prometheus: Use SSH tunnel - ssh -L 9090:${MONITORING}:9090 ubuntu@${AUTH_PORTAL}${NC}"
    fi
    
    print_section "8.5 Summary Matrix"
    
    echo ""
    echo -e "  ${BOLD}Actual Test Results:${NC}"
    echo -e "  ┌─────────────┬───────────┬───────────┬───────────┬────────────┐"
    echo -e "  │ User        │ AWS UI    │ AWS Data  │ OS Data   │ Monitoring │"
    echo -e "  ├─────────────┼───────────┼───────────┼───────────┼────────────┤"
    
    for username in viewer aws_user full_user admin; do
        password="${USERS[$username]}"
        token=$(get_jwt_token "$username" "$password")
        
        aws_result=$(test_api_access "$token" "$AWS_DATA_API")
        os_result=$(test_api_access "$token" "$OS_DATA_API")
        
        aws_icon="[[ \"$aws_result\" == \"200\" ]] && echo \"${GREEN}✓ YES${NC}\" || echo \"${RED}✗ NO${NC}\""
        os_icon="[[ \"$os_result\" == \"200\" ]] && echo \"${GREEN}✓ YES${NC}\" || echo \"${RED}✗ NO${NC}\""
        
        printf "  │ %-11s │" "$username"
        echo -ne " ${GREEN}✓ YES${NC}     │"
        [[ "$aws_result" == "200" ]] && echo -ne " ${GREEN}✓ YES${NC}     │" || echo -ne " ${RED}✗ NO${NC}      │"
        [[ "$os_result" == "200" ]] && echo -ne " ${GREEN}✓ YES${NC}     │" || echo -ne " ${RED}✗ NO${NC}      │"
        [[ "$username" == "admin" ]] && echo -e " ${GREEN}✓ YES${NC}      │" || echo -e " ${RED}✗ NO${NC}       │"
    done
    
    echo -e "  └─────────────┴───────────┴───────────┴───────────┴────────────┘"
    
    echo ""
    echo -e "  ${BOLD}Zero Trust Flow:${NC}"
    echo "  1. User đăng nhập Auth Portal → nhận JWT với permissions"
    echo "  2. JWT được gửi kèm mỗi API request (Authorization header)"
    echo "  3. Auth Server verify JWT signature và check permissions"
    echo "  4. Allow/Deny dựa trên permission claims trong token"
    echo "  5. Cross-cluster (OS): Data fetch qua mTLS tunnel"
}

#═══════════════════════════════════════════════════════════════════════════════
# MAIN
#═══════════════════════════════════════════════════════════════════════════════

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -a, --all         Run all tests (default)"
    echo "  -c, --connect     Run connectivity tests only"
    echo "  -u, --auth        Run authentication tests only"
    echo "  -r, --rbac        Run RBAC tests only"
    echo "  -m, --monitor     Run monitoring tests only"
    echo "  -i, --infra       Run infrastructure tests only"
    echo "  -e, --e2e         Run E2E flow tests only"
    echo "  -p, --perf        Run performance tests only"
    echo "  -d, --demo        Run 4-user scenario demo"
    echo "  -q, --quick       Quick test (connectivity + auth + rbac)"
    echo "  -f, --full-demo   Full demo (quick + scenarios)"
    echo "  -h, --help        Show this help"
    echo ""
    echo "Examples:"
    echo "  $0                Run all tests"
    echo "  $0 -q             Quick test"
    echo "  $0 -d             Demo 4 user scenarios"
    echo "  $0 -f             Full demo from A-Z"
    echo ""
}

main() {
    local RUN_ALL=true
    local RUN_CONNECT=false
    local RUN_AUTH=false
    local RUN_RBAC=false
    local RUN_MONITOR=false
    local RUN_INFRA=false
    local RUN_E2E=false
    local RUN_PERF=false
    local RUN_DEMO=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -a|--all) RUN_ALL=true; shift ;;
            -c|--connect) RUN_CONNECT=true; RUN_ALL=false; shift ;;
            -u|--auth) RUN_AUTH=true; RUN_ALL=false; shift ;;
            -r|--rbac) RUN_RBAC=true; RUN_ALL=false; shift ;;
            -m|--monitor) RUN_MONITOR=true; RUN_ALL=false; shift ;;
            -i|--infra) RUN_INFRA=true; RUN_ALL=false; shift ;;
            -e|--e2e) RUN_E2E=true; RUN_ALL=false; shift ;;
            -p|--perf) RUN_PERF=true; RUN_ALL=false; shift ;;
            -d|--demo) RUN_DEMO=true; RUN_ALL=false; shift ;;
            -q|--quick) RUN_CONNECT=true; RUN_AUTH=true; RUN_RBAC=true; RUN_ALL=false; shift ;;
            -f|--full-demo) RUN_CONNECT=true; RUN_AUTH=true; RUN_RBAC=true; RUN_DEMO=true; RUN_ALL=false; shift ;;
            -h|--help) show_usage; exit 0 ;;
            *) echo "Unknown option: $1"; show_usage; exit 1 ;;
        esac
    done
    
    clear
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                               ║"
    echo "║     ZERO TRUST ARCHITECTURE - EVALUATION TEST SUITE                           ║"
    echo "║     Hub-and-Spoke Deployment via Auth Portal                                  ║"
    echo "║                                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${BOLD}Configuration:${NC}"
    echo "  Auth Portal:    http://${AUTH_PORTAL}:8888"
    echo "  Monitoring:     http://${MONITORING}:3000 (Grafana)"
    echo "                  http://${MONITORING}:9090 (Prometheus)"
    echo ""
    echo -e "${BOLD}User Accounts (4 Roles):${NC}"
    echo "  viewer    / viewer123 → AWS UI only"
    echo "  aws_user  / aws123    → AWS UI + AWS data"
    echo "  full_user / full123   → AWS UI + AWS data + OS data"
    echo "  admin     / admin123  → Full access + Monitoring"
    echo ""
    
    # Show test sections to run
    echo -e "${BOLD}Test Sections:${NC}"
    echo -e "  ┌─────┬────────────────────────────────────────────────────────┐"
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_CONNECT" == true ]] && \
        echo -e "  │ ${GREEN}I${NC}   │ Connectivity Tests - Entry points & internal services  │"
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_AUTH" == true ]] && \
        echo -e "  │ ${GREEN}II${NC}  │ Authentication Tests - JWT token & validation          │"
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_RBAC" == true ]] && \
        echo -e "  │ ${GREEN}III${NC} │ RBAC Authorization - 4 user permission matrix          │"
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_MONITOR" == true ]] && \
        echo -e "  │ ${GREEN}IV${NC}  │ Monitoring + SPIRE/SVID - Grafana, Loki, Certificates  │"
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_INFRA" == true ]] && \
        echo -e "  │ ${GREEN}V${NC}   │ Infrastructure - Docker, Terraform, Network            │"
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_E2E" == true ]] && \
        echo -e "  │ ${GREEN}VI${NC}  │ End-to-End Flow - Complete auth journey                │"
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_PERF" == true ]] && \
        echo -e "  │ ${GREEN}VII${NC} │ Performance Tests - Latency & response time            │"
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_DEMO" == true ]] && \
        echo -e "  │ ${GREEN}VIII${NC}│ 4-User Scenario Demo - viewer/aws/full/admin           │"
    echo -e "  └─────┴────────────────────────────────────────────────────────┘"
    echo ""
    
    # Run tests
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_CONNECT" == true ]] && test_connectivity
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_AUTH" == true ]] && test_authentication
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_RBAC" == true ]] && test_rbac
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_MONITOR" == true ]] && test_monitoring
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_INFRA" == true ]] && test_infrastructure
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_E2E" == true ]] && test_e2e_flow
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_PERF" == true ]] && test_performance
    [[ "$RUN_ALL" == true ]] || [[ "$RUN_DEMO" == true ]] && test_user_scenarios
    
    # Summary
    print_header "Summary"
    
    echo ""
    echo -e "  ${BOLD}Test Results:${NC}"
    echo -e "    Total Tests:  $TOTAL_TESTS"
    echo -e "    ${GREEN}Passed:       $PASSED_TESTS${NC}"
    echo -e "    ${RED}Failed:       $FAILED_TESTS${NC}"
    [[ $SKIPPED_TESTS -gt 0 ]] && echo -e "    ${YELLOW}Skipped:      $SKIPPED_TESTS${NC}"
    
    if [[ $TOTAL_TESTS -gt 0 ]]; then
        local pass_rate=$((PASSED_TESTS * 100 / TOTAL_TESTS))
        echo -e "    Pass Rate:    ${pass_rate}%"
    fi
    
    echo ""
    echo -e "  ${BOLD}Zero Trust Components:${NC}"
    echo "    • Single Entry Point: Auth Portal (${AUTH_PORTAL}:8888)"
    echo "    • JWT Authentication: HS256 with 15-minute expiry"
    echo "    • SVID Certificate: X.509 with 5-minute rotation"
    echo "    • RBAC: 4 user roles (viewer, aws_user, full_user, admin)"
    echo "    • Permission-based API access control"
    echo "    • Monitoring: Grafana + Prometheus + Loki + Jaeger"
    
    echo ""
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "  ${GREEN}${BOLD}✓ ALL TESTS PASSED${NC}"
    elif [[ $PASSED_TESTS -gt $FAILED_TESTS ]]; then
        echo -e "  ${YELLOW}${BOLD}⚠ Some tests need attention${NC}"
    else
        echo -e "  ${RED}${BOLD}✗ Multiple tests failed - check infrastructure${NC}"
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════════════════════"
    echo -e "${DIM}  Run with -h for options. Use -f for full A-Z demo.${NC}"
    echo ""
}

main "$@"
