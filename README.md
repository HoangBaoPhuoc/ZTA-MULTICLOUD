# 🔐 Zero Trust Architecture - Hub-and-Spoke Multi-Cloud

<div align="center">

![Zero Trust](https://img.shields.io/badge/Security-Zero%20Trust-blue)
![OpenStack](https://img.shields.io/badge/Platform-OpenStack-red)
![Terraform](https://img.shields.io/badge/IaC-Terraform-purple)
![Ansible](https://img.shields.io/badge/Config-Ansible-black)
![SPIRE](https://img.shields.io/badge/Identity-SPIRE%201.8.7-orange)

**Enterprise Zero Trust Architecture with SPIRE, mTLS, and WireGuard Hub-Spoke**

[Quick Start](#-quick-start) • [Architecture](#-architecture) • [Components](#-components) • [Testing](#-testing)

</div>

---

## 📋 Overview

Implementation of **Zero Trust Architecture (ZTA)** with **Hub-and-Spoke** network topology, featuring:

- **SPIRE** for workload identity (SVID X.509 certificates with 5-minute rotation)
- **WireGuard** for secure tunnel between gateways
- **Envoy + OPA** for policy enforcement with JWT validation
- **mTLS** for service-to-service authentication

> **"Never Trust, Always Verify"**

---

## 🏗️ Architecture

### Network Topology

```
         ┌─────────────────┐
         │    INTERNET     │
         └────────┬────────┘
                  │
                  │
                  │                                            
                  ▼                                             
     ┌──────────────────────────┐       ┌─────────────────────────────────────────┐
     │   DMZ (10.50.1.0/24)     │       │      Observability (10.40.1.0/24)       │
     │   ══════════════════     │       │      ═══════════════════════════        │
     │                          │       │                                         │
     │  ┌────────────────────┐  │       │  ┌─────────────────┐  ┌──────────────┐  │
     │  │   AUTH PORTAL ★    │  │       │  │  vm-monitoring  │  │ vm-identity  │  │
     │  │  172.10.10.170     │  │       │  │  10.40.1.10     │  │  10.40.1.20  │  │
     │  │  (THE ONLY PUBLIC) │  │       │  │  (NO public IP) │  │              │  │
     │  │                    │  │──────►│  │                 │  │              │  │
     │  │  • Login UI (:80)  │  │       │  │  • Prometheus   │  │ • SPIRE      │  │
     │  │  • JWT API (:8888) │  │       │  │  • Grafana      │  │   Server     │  │
     │  │  • WireGuard Hub   │  │       │  │  • Jaeger       │  │   (:8081)    │  │
     │  │    (10.99.0.100)   │  │       │  └─────────────────┘  └──────────────┘  │
     │  └────────────────────┘  │       │                                         │
     └──────────────────────────┘       └─────────────────────────────────────────┘
                    │                              
                    │router-dmz (HUB)    
                    │════════════════    
                    │                              
         ┌──────────┴──────────┐                   
         │   WireGuard Tunnel  │                   
         │   10.99.0.0/24      │                   
         └──────────┬──────────┘                   
                    │                              
         ┌──────────┴───────────────────────┐
         │                                  │
         ▼                                  ▼
┌─────────────────────────┐    ┌─────────────────────────┐
│  AWS Cloud              │    │  OS Cloud               │
│  (10.20.2.0/24)         │    │  (10.10.2.0/24)         │
│  ═══════════════        │    │  ═════════════          │
│                         │    │                         │
│  ┌───────────────────┐  │    │  ┌───────────────────┐  │
│  │  AWS GATEWAY      │  │    │  │  OS GATEWAY       │  │
│  │  10.20.2.5        │  │    │  │  10.10.2.5        │  │
│  │  WG: 10.99.0.1    │  ◄─────► │  WG: 10.99.0.2    │  │
│  │                   │   mTLS   │                   │  │
│  │  • OPA (:9191)    │  │    │  │  • Envoy mTLS     │  │
│  │  • Envoy (:8080)  │  │    │  │    (:443)         │  │
│  │  • SPIRE Agent    │  │    │  │  • SPIRE Agent    │  │
│  └───────────────────┘  │    │  └───────────────────┘  │
│           │             │    │           │             │
│  ┌───────────────────┐  │    │  ┌───────────────────┐  │
│  │  AWS Cluster      │  │    │  │  OS Cluster       │  │
│  │  10.20.2.10       │  │    │  │  10.10.2.10       │  │
│  │  K3s (UI Pods)    │  │    │  │  K3s (Backend)    │  │
│  └───────────────────┘  │    │  └───────────────────┘  │
└─────────────────────────┘    └─────────────────────────┘
```

### Security Layers

| Layer             | Technology    | Description                                          |
|-------------------|---------------|------------------------------------------------------|
| **L1: Network**   | Hub-and-Spoke | Isolated networks, no direct cross-network           |
| **L2: Tunnel**    | WireGuard     | Encrypted tunnel between Auth Portal → Gateways      |
| **L3: Identity**  | SPIRE/SVID    | Workload identity with 5-minute certificate rotation |
| **L4: AuthN**     | JWT (HS256)   | Token-based authentication, 15-minute lifetime       |
| **L5: AuthZ**     | OPA/Rego      | Real-time policy decisions                           |
| **L6: Transport** | mTLS          | Mutual TLS between AWS ↔ OS Gateways                 |

---

## 🔧 Components

### VMs & Services

| VM                 | Network       | IP         | Public           | Services                                    |
|--------------------|---------------|------------|:----------------:|---------------------------------------------|
| **vm-auth-portal** | DMZ           | 10.50.1.10 | ✅ 172.10.10.170 | Login UI, JWT Server, WireGuard Hub         |
| **vm-identity**    | Observability | 10.40.1.20 |        ❌        | SPIRE Server                                |
| **vm-monitoring**  | Observability | 10.40.1.10 |        ❌        | Prometheus, Grafana, Jaeger, Loki, Promtail |
| **vm-aws-gateway** | Cloud AWS     | 10.20.2.5  |        ❌        | OPA, Envoy, SPIRE Agent, WG Spoke           |
| **vm-os-gateway**  | Cloud OS      | 10.10.2.5  |        ❌        | Envoy mTLS, SPIRE Agent, WG Spoke           |
| **aws-master**     | Cloud AWS     | 10.20.2.10 |        ❌        | K3s - UI Pods                               |
| **os-master**      | Cloud OS      | 10.10.2.10 |        ❌        | K3s - Backend API Pods                      |

> ⚠️ **Zero Trust**: Only Auth Portal has public IP. All other services accessed via Auth Portal proxy or SSH tunnel.

### Request Flow

```
┌──────────┐    ┌──────────────┐    ┌─────────────────┐    ┌───────────────┐    ┌──────────────┐
│  User    │───►│ Auth Portal  │───►│  AWS Gateway    │───►│  OS Gateway   │───►│  Backend Pod │
│          │    │              │    │                 │    │               │    │              │
│          │    │ 1. Login     │    │ 3. OPA Check    │    │ 5. mTLS       │    │ 6. Response  │
│          │    │ 2. Get JWT   │    │ 4. Route        │    │    Terminate  │    │              │
└──────────┘    └──────────────┘    └─────────────────┘    └───────────────┘    └──────────────┘
                       │                    │                      │
                       │              WireGuard Tunnel             │
                       └───────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- OpenStack environment with Neutron networking
- Terraform >= 1.0
- Ansible >= 2.9
- SSH keypair (`~/.ssh/id_rsa_zerotrust`)

### Deploy Infrastructure

```bash
# 1. Clone and setup
cd /etc/zta-multicloud
cp .env.example .env

# 2. Deploy Terraform (VMs + Networks)
cd terraform-openstack
source /etc/kolla/zerotrust-openrc.sh
terraform init && terraform apply -auto-approve

# 3. Deploy ZTA Stack with Ansible
cd ../ansible-zta
ansible-playbook -i inventory/hosts.ini deploy-zta-hub-spoke.yml
```

### Or Use All-in-One Script

```bash
./zta-full-deploy.sh
```

---

## 🧪 Testing

### User Accounts (RBAC Demo)

| User          | Password  | Permissions                     | Access                           |
|---------------|-----------|---------------------------------|----------------------------------|
| **viewer**    | viewer123 | `aws:ui`                        | AWS UI only                      |
| **aws_user**  | aws123    | `aws:ui`, `aws:read`            | AWS UI + AWS data API            |
| **full_user** | full123   | `aws:ui`, `aws:read`, `os:read` | AWS UI + AWS data + OS data      |
| **admin**     | admin123  | All permissions                 | Full access including monitoring |

### API Endpoints

| Endpoint        | Method | Auth             | Description                  |
|-----------------|--------|------------------|------------------------------|
| `/api/login`    | POST   | None             | Get JWT token                |
| `/api/users`    | GET    | JWT              | List users                   |
| `/api/aws/data` | GET    | JWT + `aws:read` | AWS data (requires aws:read) |
| `/api/os/data`  | GET    | JWT + `os:read`  | OS data (requires os:read)   |

### E2E Test Commands

```bash
# 1. Get JWT Token for admin
JWT=$(curl -s -X POST http://172.10.10.170:8888/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# 2. Test AWS Data API
curl -s -H "Authorization: Bearer $JWT" http://172.10.10.170:8888/api/aws/data
# Expected: {"data": {"service": "AWS Cluster", ...}}

# 3. Test OS Data API  
curl -s -H "Authorization: Bearer $JWT" http://172.10.10.170:8888/api/os/data
# Expected: {"data": {"service": "OS Cluster", ...}}

# 4. Test RBAC - viewer cannot access /api/aws/data
VIEWER_JWT=$(curl -s -X POST http://172.10.10.170:8888/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"viewer","password":"viewer123"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

curl -s -H "Authorization: Bearer $VIEWER_JWT" http://172.10.10.170:8888/api/aws/data
# Expected: {"error": "Insufficient permissions"}
```

### Run Full Evaluation Test

```bash
# Run all tests
./zta-evaluation-test.sh

# Run demo scenario only
./zta-evaluation-test.sh -d

# Run full demo with explanations
./zta-evaluation-test.sh -f
```

### Test Results Summary

```
╔═════════════════════════════════════════════════════════════════╗
║           🎯 ZTA EVALUATION TEST SUMMARY                        ║
╠═════════════════════════════════════════════════════════════════╣
║  ✅ Test Passed: 40/40 (100%)                                   ║
║                                                                 ║
║  Test Sections (8 categories):                                  ║
║  ┌─────┬──────────────────────────────────────────────────────┐ ║
║  │ I   │ Connectivity - Entry points & internal services    ✓ │ ║
║  │ II  │ Authentication - JWT token & validation            ✓ │ ║
║  │ III │ RBAC Authorization - 4 user permission matrix      ✓ │ ║
║  │ IV  │ Monitoring + SPIRE/SVID - Grafana, Loki, Certs     ✓ │ ║
║  │ V   │ Infrastructure - Docker, Terraform, Network        ✓ │ ║
║  │ VI  │ End-to-End Flow - Complete auth journey            ✓ │ ║
║  │ VII │ Performance - Latency & response time              ✓ │ ║
║  │ VIII│ 4-User Scenario Demo - viewer/aws/full/admin       ✓ │ ║
║  └─────┴──────────────────────────────────────────────────────┘ ║
║                                                                 ║
║  Key Metrics:                                                   ║
║  • Auth Latency: ~12ms (excellent)                              ║
║  • Portal Response: ~1ms                                        ║
║  • JWT TTL: 15 minutes                                          ║
║  • SVID Rotation: 5 minutes                                     ║
║  • Prometheus Targets: 3 active                                 ║
║  • Terraform Resources: 61 managed                              ║
╚═════════════════════════════════════════════════════════════════╝
```

### Verify SPIRE SVIDs

```bash
# On AWS Gateway
sudo /opt/spire/bin/spire-agent api fetch x509 -socketPath /opt/spire/run/agent.sock
# Shows: spiffe://zta.local/workload/aws-service

# On OS Gateway  
sudo /opt/spire/bin/spire-agent api fetch x509 -socketPath /opt/spire/run/agent.sock
# Shows: spiffe://zta.local/workload/os-service
```

### Verify WireGuard Tunnel

```bash
# On Auth Portal (Hub)
sudo wg show wg0
# Should show 2 peers: 10.99.0.1 (AWS) and 10.99.0.2 (OS)
```

---

## 📁 Project Structure

```
/etc/zta-multicloud/
├── terraform-openstack/
│   ├── main.tf              # Infrastructure as Code (61 resources)
│   └── terraform.tfstate    # Terraform state
├── ansible-zta/
│   ├── inventory/
│   │   ├── hosts.ini        # VM inventory (production)
│   │   └── hosts.ini.example # Example inventory template
│   ├── site.yml             # Main deployment playbook
│   ├── ansible.cfg          # Ansible configuration
│   └── roles/               # Ansible roles
├── docs/
│   ├── architecture.md      # Detailed ZTA architecture
│   └── ssh-reference.md     # SSH tunnel quick reference
├── logs/                    # Deployment logs
├── zta-full-deploy.sh       # All-in-one deploy script
├── zta-evaluation-test.sh   # E2E test script (40 tests, 8 sections)
└── cleanup.sh               # Cleanup script
```

---

## 🔑 Credentials

| Service     | Username  | Password  | Access         |
|-------------|-----------|-----------|----------------|
| Auth Portal | viewer    | viewer123 | AWS UI only    |
| Auth Portal | aws_user  | aws123    | AWS UI + data  |
| Auth Portal | full_user | full123   | AWS + OS data  |
| Auth Portal | admin     | admin123  | Full access    |
| Grafana     | admin     | admin     | Via SSH tunnel |

### Access Monitoring (No Public IP - Zero Trust)

```bash
# All monitoring services require SSH tunnel through Auth Portal

# Grafana (Dashboards)
ssh -L 3000:10.40.1.10:3000 -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170
# Open: http://localhost:3000 (admin/admin)

# Prometheus (Metrics - 3 active targets)
ssh -L 9090:10.40.1.10:9090 -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170
# Open: http://localhost:9090

# Jaeger (Distributed Tracing)
ssh -L 16686:10.40.1.10:16686 -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170
# Open: http://localhost:16686

# Loki (Log Aggregation) - accessed via Grafana datasource
# Port 3100 internal only
```

---

## 📊 Ports Reference

| Port      | Service        | Location       |
|-----------|----------------|----------------|
| 80        | Auth Portal UI | vm-auth-portal |
| 8888      | JWT API Server | vm-auth-portal |
| 8080      | Envoy Proxy    | vm-aws-gateway |
| 9191      | OPA gRPC       | vm-aws-gateway |
| 443       | Envoy mTLS     | vm-os-gateway  |
| 8081      | SPIRE Server   | vm-identity    |
| 51820/UDP | WireGuard      | All gateways   |
| 3000      | Grafana        | vm-monitoring  |
| 9090      | Prometheus     | vm-monitoring  |
| 3100      | Loki           | vm-monitoring  |
| 16686     | Jaeger         | vm-monitoring  |

---

## 🛠️ Troubleshooting

### SPIRE Agent Not Connecting
```bash
# Check agent logs
sudo tail -f /var/log/spire-agent.log

# Verify connectivity to SPIRE server
nc -zv 10.40.1.20 8081
```

### WireGuard Tunnel Down
```bash
# Check WireGuard status
sudo wg show wg0

# Restart WireGuard
sudo systemctl restart wg-quick@wg0
```

### OPA Returning 403 with Valid JWT
```bash
# Check OPA logs
docker logs opa

# Test OPA policy directly
curl localhost:8181/v1/data/envoy/authz/allow
```

---

## 📜 License

MIT License - See [LICENSE](LICENSE)

---

<div align="center">

**Built for Zero Trust Multi-Cloud Security**

</div>
