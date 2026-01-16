# 🔐 Zero Trust Architecture - Multi-Cloud Implementation

<div align="center">

![Zero Trust](https://img.shields.io/badge/Security-Zero%20Trust-blue)
![OpenStack](https://img.shields.io/badge/Platform-OpenStack-red)
![Terraform](https://img.shields.io/badge/IaC-Terraform-purple)
![Ansible](https://img.shields.io/badge/Config-Ansible-black)
![License](https://img.shields.io/badge/License-MIT-green)

**Enterprise-grade Zero Trust Architecture for Multi-Cloud Environments**

[Quick Start](#-quick-start) • [User Guide](#-user-guide) • [Admin Guide](#-admin-guide) • [Architecture](#-architecture) • [Evaluation](#-evaluation)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Quick Start](#-quick-start)
- [User Guide](#-user-guide)
- [Admin Guide](#-admin-guide)
- [Architecture](#-architecture)
- [Configuration](#-configuration)
- [Evaluation & Testing](#-evaluation)
- [Troubleshooting](#-troubleshooting)

---

## 🎯 Overview

This project implements a complete **Zero Trust Architecture (ZTA)** across a multi-cloud environment (AWS + OpenStack simulation). It follows the core Zero Trust principles:

> **"Never Trust, Always Verify"**

### Key Features

| Feature | Technology | Description |
|---------|-----------|-------------|
| 🔑 **Identity Provider** | Keycloak 23.0.4 | JWT-based authentication with 15-min token lifetime |
| 📜 **Policy Engine** | OPA (Open Policy Agent) | Real-time policy decisions using Rego language |
| 🛡️ **Service Mesh** | Envoy Proxy v1.28 | JWT validation + mTLS enforcement |
| 🔒 **Workload Identity** | SPIRE 1.8.7 | Auto-rotating X.509 certificates (5-min TTL) |
| 🌐 **Secure Tunnel** | WireGuard | Encrypted cross-cloud communication |
| 📊 **Observability** | Prometheus + Grafana + Loki | Full-stack monitoring & logging |

### Security Layers

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                          ZERO TRUST ARCHITECTURE FLOW                                │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                      │
│                              ┌─────────────────┐                                    │
│                              │    INTERNET     │                                    │
│                              │     (Users)     │                                    │
│                              └────────┬────────┘                                    │
│                                       │                                             │
│                                       ▼                                             │
│  ╔═══════════════════════════════════════════════════════════════════════════════╗ │
│  ║                    AWS GATEWAY - Single Entry Point                           ║ │
│  ║                         (Public IP: Floating)                                 ║ │
│  ╠═══════════════════════════════════════════════════════════════════════════════╣ │
│  ║  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ║ │
│  ║  │   Envoy     │───►│  Keycloak   │───►│    OPA      │───►│   mTLS      │    ║ │
│  ║  │  (Gateway)  │    │  (AuthN)    │    │  (Policy)   │    │  (Tunnel)   │    ║ │
│  ║  │  :80/:8080  │    │  JWT Token  │    │  Rego Rules │    │  WireGuard  │    ║ │
│  ║  └─────────────┘    └─────────────┘    └─────────────┘    └──────┬──────┘    ║ │
│  ╚══════════════════════════════════════════════════════════════════╪═══════════╝ │
│                                                                      │              │
│                          PRIVATE NETWORK (Internal Only)             │              │
│        ┌─────────────────────────────────────────────────────────────┘              │
│        │                                                                            │
│        ▼                                                                            │
│  ┌───────────────┐         ┌───────────────┐         ┌───────────────┐             │
│  │   Frontend    │         │   Monitoring  │         │    Backend    │             │
│  │   (AWS K3s)   │         │   (Keycloak,  │         │   (OS K3s)    │             │
│  │   :30090      │         │   Prometheus, │         │   :30091      │             │
│  │               │         │   Grafana)    │         │               │             │
│  └───────────────┘         └───────────────┘         └───────────────┘             │
│                                                                                      │
├─────────────────────────────────────────────────────────────────────────────────────┤
│  Security Layers:                                                                    │
│    Layer 1: Perimeter Defense   → AWS Gateway (single entry, all traffic filtered) │
│    Layer 2: Identity Verification → Keycloak JWT (15-min lifetime)                  │
│    Layer 3: Policy Enforcement   → OPA Rego (real-time decisions)                  │
│    Layer 4: Transport Security   → mTLS + WireGuard (encrypted tunnel)             │
│    Layer 5: Workload Identity    → SPIRE SVID (5-min auto-rotation)                │
│    Layer 6: Network Segmentation → VPC Isolation (no direct Internet access)       │
└─────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- OpenStack cloud access with admin privileges
- Ubuntu 22.04+ control node
- SSH key pair configured
- OpenStack RC file sourced

### One-Command Deployment

```bash
# 1. Clone repository
git clone https://github.com/your-org/zta-multicloud.git
cd zta-multicloud

# 2. Configure environment
cp .env.example .env
nano .env  # Edit your settings

# 3. Source OpenStack credentials
source ~/your-openstack-rc.sh

# 4. Deploy everything
./zta-full-deploy.sh
```

**⏱️ Deployment Time:** ~15-20 minutes

---

## 👤 User Guide

This section is for **end users** who want to access the Zero Trust protected application.

### Accessing the Application

| Service | URL | Description |
|---------|-----|-------------|
| 🌐 **Web Application** | `http://<AWS_GATEWAY_IP>/` | Main application frontend |

> **Default IPs after deployment:** AWS Gateway = `172.10.10.181`

### Login Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    USER AUTHENTICATION FLOW                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Open Browser ──► http://172.10.10.181/                      │
│                                                                  │
│  2. Click "Login (Keycloak)"                                    │
│     ├── Enter Username: demo                                    │
│     └── Enter Password: demo123                                 │
│                                                                  │
│  3. Upon success: "Authentication successful! JWT stored."      │
│                                                                  │
│  4. Click "Fetch Secure Data"                                   │
│     └── View data from Private Cloud (OS Gateway)              │
│                                                                  │
│  5. Click "Logout" when done                                    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Test Credentials

| Username | Password | Role | Access Level |
|----------|----------|------|--------------|
| `demo` | `demo123` | User | Read access to `/api/secure-data` |

### What Happens Behind the Scenes

When you click "Fetch Secure Data":

1. **JWT Validation**: Envoy checks your token with Keycloak
2. **Policy Check**: OPA evaluates if you can access `/api/`
3. **mTLS Tunnel**: Request goes through encrypted WireGuard tunnel
4. **Certificate Verification**: OS Gateway verifies client certificate
5. **Backend Response**: Data returned from Private Cloud

### Troubleshooting for Users

| Issue | Solution |
|-------|----------|
| "Please login first!" | Click Login button and authenticate |
| "Authentication failed" | Check username/password (demo/demo123) |
| "Access denied: HTTP 401" | Token expired, login again |
| "Access denied: HTTP 403" | You don't have permission for this resource |
| Page not loading | Check if AWS Gateway is accessible |

---

## 🔧 Admin Guide

This section is for **administrators** who manage the Zero Trust infrastructure.

### Infrastructure Overview

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                           INFRASTRUCTURE TOPOLOGY                                       │
│                      (Single Entry Point Architecture)                                  │
├────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                         │
│                                   INTERNET                                              │
│                                      │                                                  │
│                                      │ All external traffic                            │
│                                      ▼                                                  │
│  ╔════════════════════════════════════════════════════════════════════════════════════╗│
│  ║                 AWS GATEWAY (Single Public Entry Point)                            ║│
│  ║                      Floating IP: 172.10.10.181                                    ║│
│  ║  ┌────────────────────────────────────────────────────────────────────────────┐   ║│
│  ║  │  Envoy Proxy (:80/:8080)  │  OPA Policy (:8181)  │  WireGuard (:51820)    │   ║│
│  ║  │  • JWT Validation         │  • Access Control     │  • Encrypted Tunnel   │   ║│
│  ║  │  • Route Management       │  • Rego Policies      │  • mTLS Certs         │   ║│
│  ║  └────────────────────────────────────────────────────────────────────────────┘   ║│
│  ╚═══════════════════════════╤════════════════════════════════════════════════════════╝│
│                               │                                                         │
│            INTERNAL NETWORK   │  (No Direct Internet Access)                           │
│      ┌────────────────────────┼─────────────────────────────────┐                      │
│      │                        │                                 │                      │
│      ▼                        ▼                                 ▼                      │
│  ┌───────────────┐     ┌────────────────┐              ┌───────────────────┐          │
│  │  AWS CLOUD    │     │  MANAGEMENT    │   WireGuard  │   OPENSTACK CLOUD │          │
│  │  10.20.2.0/24 │     │  10.30.1.0/24  │   Tunnel     │   10.10.2.0/24    │          │
│  │               │     │                │  ─────────►  │                   │          │
│  │ ┌───────────┐ │     │ ┌────────────┐ │              │ ┌───────────────┐ │          │
│  │ │  K3s      │ │     │ │ Keycloak   │ │              │ │  OS Gateway   │ │          │
│  │ │  Frontend │ │     │ │ (Identity) │ │              │ │  (mTLS :443)  │ │          │
│  │ │  :30090   │ │     │ │ :8080      │ │              │ │               │ │          │
│  │ └───────────┘ │     │ ├────────────┤ │              │ │ ┌───────────┐ │ │          │
│  │               │     │ │ SPIRE      │ │              │ │ │ K3s       │ │ │          │
│  │               │     │ │ Server     │ │              │ │ │ Backend   │ │ │          │
│  │               │     │ │ :8081      │ │              │ │ │ :30091    │ │ │          │
│  │               │     │ ├────────────┤ │              │ │ └───────────┘ │ │          │
│  │               │     │ │ Prometheus │ │              │ │               │ │          │
│  │               │     │ │ Grafana    │ │              │ │               │ │          │
│  │               │     │ │ Loki       │ │              │ └───────────────┘ │          │
│  │               │     │ └────────────┘ │              │                   │          │
│  └───────────────┘     └────────────────┘              └───────────────────┘          │
│                                                                                         │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  Traffic Flow:                                                                          │
│    Internet → AWS Gateway (Auth+Policy) → WireGuard Tunnel → OS Gateway → Backend     │
│                     ▲                                              │                    │
│                     └──────────── Response Path ◄──────────────────┘                   │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Admin Access Points

| Service | URL | Credentials | Purpose |
|---------|-----|-------------|---------|
| **Grafana** | `http://<MONITORING_IP>:3000` | admin / admin | Metrics Dashboard |
| **Prometheus** | `http://<MONITORING_IP>:9090` | - | Query Metrics |
| **Loki** | `http://<MONITORING_IP>:3100` | - | Log Aggregation |
| **Jaeger** | `http://<MONITORING_IP>:16686` | - | Distributed Tracing |
| **Keycloak Admin** | `http://<IDENTITY_IP>:8080` | admin / Admin@123 | Identity Management |
| **OPA API** | `http://<AWS_GATEWAY_IP>:8181` | - | Policy Management |
| **Envoy Admin (AWS)** | `http://<AWS_GATEWAY_IP>:9901` | - | Proxy Stats |
| **Envoy Admin (OS)** | `http://<OS_GATEWAY_IP>:9901` | - | Proxy Stats |

> **Default IPs:** Monitoring=`172.10.10.172`, Identity=`10.30.1.20`, AWS=`172.10.10.181`, OS=`172.10.10.171`

### SSH Access

```bash
# SSH to any VM
SSH_KEY="~/.ssh/openstack-key.pem"
SSH_OPTS="-o StrictHostKeyChecking=no -o IdentitiesOnly=yes"

# AWS Gateway
ssh $SSH_OPTS -i $SSH_KEY ubuntu@172.10.10.181

# OS Gateway
ssh $SSH_OPTS -i $SSH_KEY ubuntu@172.10.10.171

# Monitoring
ssh $SSH_OPTS -i $SSH_KEY ubuntu@172.10.10.172
```

### Managing Components

#### Keycloak - User Management

```bash
# SSH to Monitoring VM, then to Identity VM
ssh ubuntu@172.10.10.172
ssh ubuntu@10.30.1.20

# Access Keycloak CLI
docker exec -it keycloak /opt/keycloak/bin/kcadm.sh

# Create new user
docker exec keycloak /opt/keycloak/bin/kcadm.sh create users -r zta \
  -s username=newuser -s enabled=true
docker exec keycloak /opt/keycloak/bin/kcadm.sh set-password -r zta \
  --username newuser --new-password newpass123
```

#### OPA - Policy Management

```bash
# SSH to AWS Gateway
ssh ubuntu@172.10.10.181

# View current policies
curl http://localhost:8181/v1/policies

# Update policy
sudo nano /opt/opa/policy.rego
sudo docker restart opa
```

#### Certificate Management

```bash
# View certificate expiry
ssh ubuntu@172.10.10.181 "openssl x509 -in /opt/certs/ca-cert.pem -noout -dates"

# Regenerate certificates (if needed)
ssh ubuntu@172.10.10.181 "cd /opt/certs && sudo ./regenerate-certs.sh"
```

#### Service Management

```bash
# Check service status
ssh ubuntu@172.10.10.181 "sudo docker ps"
ssh ubuntu@172.10.10.172 "sudo systemctl status spire-server"

# Restart services
ssh ubuntu@172.10.10.181 "sudo docker restart envoy-aws opa"
ssh ubuntu@172.10.10.171 "sudo docker restart envoy-os"

# View logs
ssh ubuntu@172.10.10.181 "sudo docker logs envoy-aws --tail 100"
ssh ubuntu@172.10.10.181 "sudo docker logs opa --tail 100"
```

### Monitoring & Alerting

#### Grafana Dashboards

1. Open `http://172.10.10.172:3000`
2. Login: admin / admin
3. Add Data Sources:
   - Prometheus: `http://localhost:9090`
   - Loki: `http://localhost:3100`

#### Key Metrics to Monitor

| Metric | Query | Alert Threshold |
|--------|-------|-----------------|
| Auth Failures | `sum(rate(envoy_http_downstream_rq_4xx[5m]))` | > 10/min |
| Response Time | `histogram_quantile(0.95, envoy_http_downstream_rq_time_bucket)` | > 500ms |
| OPA Decisions | `opa_decision_total{result="deny"}` | > 100/min |
| Certificate Expiry | Custom script | < 30 days |

### Backup & Recovery

```bash
# Backup Keycloak
ssh ubuntu@10.30.1.20 "docker exec keycloak /opt/keycloak/bin/kc.sh export --dir /tmp/backup"

# Backup OPA Policies
scp ubuntu@172.10.10.181:/opt/opa/*.rego ./backup/

# Backup Certificates
scp ubuntu@172.10.10.181:/opt/certs/*.pem ./backup/certs/
```

---

## 🏗️ Architecture

### Component Details

#### Identity Layer (Keycloak)
- **Realm**: `zta`
- **Client**: `zta-web` (public client, direct access grants)
- **Token Lifetime**: 15 minutes
- **Supported Flows**: Password Grant, Authorization Code

#### Policy Layer (OPA)
- **Decision Endpoint**: `:9191` (gRPC for Envoy)
- **Management API**: `:8181` (REST)
- **Policies**:
  - `policy.rego`: HTTP authorization rules
  - `spiffe_policy.rego`: Service-to-service authorization

#### Gateway Layer (Envoy)
- **AWS Gateway** (`:8080` → `:80` via iptables):
  - JWT validation against Keycloak
  - Route `/auth/token` → Keycloak
  - Route `/api/*` → OS Gateway (mTLS)
  - Route `/` → Frontend K3s

- **OS Gateway** (`:443` TLS):
  - mTLS client certificate validation
  - Route `/api/*` → Backend K3s

#### Network Layer (WireGuard)
- **AWS Gateway**: `10.99.0.1/24`
- **OS Gateway**: `10.99.0.2/24`
- **Port**: UDP 51820

---

## ⚙️ Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

See [.env.example](.env.example) for all available options.

### Key Configuration Files

| File | Purpose |
|------|---------|
| `.env` | Environment variables |
| `ansible-zta/site.yml` | Main Ansible playbook |
| `terraform-openstack/main.tf` | Infrastructure definition |
| `ansible-zta/inventory/hosts.ini` | Generated inventory |

---

## 📊 Evaluation

### Running Tests

```bash
# Comprehensive evaluation
./zta-evaluation-test.sh
```

### Test Categories

| Category | Tests | Description |
|----------|-------|-------------|
| **Security** | Authentication, Authorization, mTLS, Lateral Movement | Verify Zero Trust principles |
| **Operations** | Service Health, Certificate Management, Automation | Operational readiness |
| **Performance** | Latency, Throughput, Resource Usage | Performance benchmarks |
| **E2E Flow** | Complete user journey | End-to-end validation |

### Expected Results

```
Security:     ✓ Keycloak JWT, OPA Policies, mTLS, WireGuard
Operations:   ✓ Terraform IaC, Ansible Automation, Health Checks
Performance:  ✓ Auth <500ms, E2E <100ms, Throughput >10 req/s
```

---

## 🔍 Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| SSH "Permission denied" | Wrong key | Use `-o IdentitiesOnly=yes -i ~/.ssh/openstack-key.pem` |
| "Keycloak unreachable" | Network bridge down | Restart `keycloak-proxy` service |
| "JWT issuer mismatch" | Wrong issuer in Envoy | Update `aws_gateway_public_ip` in config |
| "mTLS handshake failed" | Certificate mismatch | Sync CA certificates between gateways |
| Envoy not starting | Port conflict | Check if port 8080 is in use |

### Debug Commands

```bash
# Check Envoy logs
ssh ubuntu@172.10.10.181 "sudo docker logs envoy-aws 2>&1 | tail -50"

# Test JWT manually
curl -X POST http://172.10.10.181/auth/token \
  -d "username=demo&password=demo123&grant_type=password&client_id=zta-web"

# Test mTLS
ssh ubuntu@172.10.10.181 "curl -k --cert /opt/certs/aws-client-cert.pem \
  --key /opt/certs/aws-client-key.pem https://10.99.0.2:443/api/health"

# Check WireGuard
ssh ubuntu@172.10.10.181 "sudo wg show"
```

---

## 📁 Project Structure

```
zta-multicloud/
├── .env.example                 # Environment template
├── .gitignore                   # Git ignore rules
├── README.md                    # This file
├── zta-full-deploy.sh          # Main deployment script
├── zta-evaluation-test.sh      # Comprehensive test suite
├── cleanup.sh                   # Destroy all resources
│
├── ansible-zta/                 # Ansible configuration
│   ├── ansible.cfg             # Ansible settings
│   ├── site.yml                # Main playbook
│   └── inventory/              # Generated inventory
│       ├── hosts.ini
│       └── group_vars/
│
├── terraform-openstack/         # Terraform IaC
│   └── main.tf                 # Infrastructure definition
│
└── docs/                        # Documentation
    └── architecture.md
```

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/zta-multicloud/issues)
- **Documentation**: [Wiki](https://github.com/your-org/zta-multicloud/wiki)

---

<div align="center">

**Built with ❤️ for Zero Trust Security**

</div>


