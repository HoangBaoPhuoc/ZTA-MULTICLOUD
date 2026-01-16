# ZTA Multi-Cloud SSH Quick Reference

## ⚠️ Zero Trust Architecture
**Only Auth Portal has a public IP.** All other services are accessed via:
- SSH ProxyCommand through Auth Portal
- SSH port forwarding tunnels

## 🔑 SSH Key Location
```
~/.ssh/id_rsa_zerotrust
```

## 📍 IP Addresses

| Component   | Public IP        | Internal IP | Ports                                              |
|-------------|:----------------:|-------------|----------------------------------------------------||
| Auth Portal | ✅ 172.10.10.170 | 10.50.1.10  | 80, 8888 (API), 22 (SSH)                           |
| Monitoring  |        ❌        | 10.40.1.10  | 3000 (Grafana), 9090 (Prometheus), 16686 (Jaeger)  |
| Identity    |        ❌        | 10.40.1.20  | 8081 (SPIRE)                      |
| AWS Gateway |        ❌        | 10.20.2.5   | 51820 (WireGuard), 8080 (Envoy)   |
| AWS Master  |        ❌        | 10.20.2.10  | 6443 (K3s API)                    |
| OS Gateway  |        ❌        | 10.10.2.5   | 51820 (WireGuard), 8080 (Envoy)   |
| OS Master   |        ❌        | 10.10.2.10  | 6443 (K3s API)                    |

## 🚀 Quick SSH Commands

### Direct Access (ONLY Auth Portal)
```bash
# Auth Portal - THE ONLY public entry point
ssh -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170
```

### Proxy Access (ALL other VMs via Auth Portal)
```bash
# Monitoring
ssh -o "ProxyCommand=ssh -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170" \
    -i ~/.ssh/id_rsa_zerotrust ubuntu@10.40.1.10

# Identity (SPIRE Server)
ssh -o "ProxyCommand=ssh -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170" \
    -i ~/.ssh/id_rsa_zerotrust ubuntu@10.40.1.20

# AWS Gateway
ssh -o "ProxyCommand=ssh -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170" \
    -i ~/.ssh/id_rsa_zerotrust ubuntu@10.20.2.5

# AWS Master (K3s)
ssh -o "ProxyCommand=ssh -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170" \
    -i ~/.ssh/id_rsa_zerotrust ubuntu@10.20.2.10

# OS Gateway
ssh -o "ProxyCommand=ssh -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170" \
    -i ~/.ssh/id_rsa_zerotrust ubuntu@10.10.2.5

# OS Master (K3s)
ssh -o "ProxyCommand=ssh -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170" \
    -i ~/.ssh/id_rsa_zerotrust ubuntu@10.10.2.10
```

## 🌐 Access Web Services (SSH Tunnels)

### Grafana Dashboard
```bash
# Start tunnel
ssh -L 3000:10.40.1.10:3000 -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170

# Open in browser: http://localhost:3000
# Login: admin / admin
```

### Prometheus Metrics
```bash
# Start tunnel
ssh -L 9090:10.40.1.10:9090 -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170

# Open in browser: http://localhost:9090
```

### Jaeger Tracing
```bash
# Start tunnel
ssh -L 16686:10.40.1.10:16686 -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170

# Open in browser: http://localhost:16686
```

## 🎯 Kubectl Commands (remote)

### AWS Cluster
```bash
ssh -o "ProxyCommand=ssh -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170" \
    -i ~/.ssh/id_rsa_zerotrust ubuntu@10.20.2.10 \
    'kubectl get pods -A'
```

### OS Cluster
```bash
ssh -o "ProxyCommand=ssh -W %h:%p -i ~/.ssh/id_rsa_zerotrust ubuntu@172.10.10.170" \
    -i ~/.ssh/id_rsa_zerotrust ubuntu@10.10.2.10 \
    'kubectl get pods -A'
```

## 🛠️ Helper Script
```bash
# Interactive menu
./ssh-helper.sh

# Quick reference
./ssh-helper.sh -q
```

## 👤 User Accounts (Auth Portal API)

| Username  | Password  | Permissions                                            | Quyền             |
|-----------|-----------|--------------------------------------------------------|-------------------|
| viewer    | viewer123 | aws:ui                                                 | Chỉ xem AWS UI    |
| aws_user  | aws123    | aws:ui, aws:read                                       | AWS UI + AWS data |
| full_user | full123   | aws:ui, aws:read, os:read                              | AWS + OS data     |
| admin     | admin123  | aws:ui, aws:read/write, os:read/write, monitoring:read | Full access       |

## 🔐 Get JWT Token
```bash
# Login endpoint
curl -X POST http://172.10.10.170:8888/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}'

# Extract token
TOKEN=$(curl -s -X POST http://172.10.10.170:8888/api/login \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin123"}' | \
    grep -o '"token":"[^"]*"' | cut -d'"' -f4)
```

## 🌐 Web Interfaces

| Service         | URL                       | Access Method       |
|-----------------|---------------------------|---------------------|
| Auth Portal API | http://172.10.10.170:8888 | Direct (public)     |
| Auth Portal UI  | http://172.10.10.170      | Direct (public)     |
| Grafana         | http://localhost:3000     | SSH tunnel required |
| Prometheus      | http://localhost:9090     | SSH tunnel required |
| Jaeger          | http://localhost:16686    | SSH tunnel required |
