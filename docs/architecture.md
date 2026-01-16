# ZTA Hub-and-Spoke Architecture

## Overview

Zero Trust Architecture with Hub-and-Spoke network topology for multi-cloud environments.

## Network Topology

```
                              INTERNET
                                 │
           ┌─────────────────────┼─────────────────────┐
           │                     │                     │
    ┌──────────────┐      ┌──────────────┐      ┌──────────────┐
    │     DMZ      │      │ Observability│      │   (hidden)   │
    │ 10.50.1.0/24 │      │ 10.40.1.0/24 │      │              │
    │              │      │              │      │              │
    │ Auth Portal  │      │ Monitoring   │      │              │
    │172.10.10.170 │      │ 10.40.1.10   │      │              │
    │ (ONLY PUBLIC)│      │ (NO PUB IP)  │      │              │
    │              │      │              │      │              │
    │ WireGuard Hub│      │ Identity     │      │              │
    │ 10.99.0.100  │      │ 10.40.1.20   │      │              │
    └──────────────┘      │ SPIRE Server │      │              │
           │              └──────────────┘      └──────────────┘
           │
           │         router-dmz (HUB)
           │
    ┌──────┴───────────────────────┐
    │                              │
    │    WireGuard VPN Tunnel      │
    │        10.99.0.0/24          │
    │                              │
    └──────┬───────────────┬───────┘
           │               │
    ┌──────┴─────┐  ┌──────┴─────┐
    │            │  │            │
    ▼            │  │            ▼
┌────────────────┴──┴────────────────┐
│                                    │
│  ┌────────────────────────────┐    │
│  │   AWS Network              │    │
│  │   10.20.2.0/24             │    │
│  │                            │    │
│  │   AWS Gateway: 10.20.2.5   │    │
│  │   WireGuard: 10.99.0.1     │    │
│  │   - Envoy (:8080)          │    │
│  │   - OPA (:9191)            │    │
│  │   - SPIRE Agent            │    │
│  │                            │    │
│  │   AWS Cluster: 10.20.2.10  │    │
│  │   - K3s (UI Pods)          │    │
│  └────────────────────────────┘    │
│                                    │
│  ┌────────────────────────────┐    │
│  │   OS Network               │    │
│  │   10.10.2.0/24             │    │
│  │                            │    │
│  │   OS Gateway: 10.10.2.5    │    │
│  │   WireGuard: 10.99.0.2     │    │
│  │   - Envoy mTLS (:443)      │    │
│  │   - SPIRE Agent            │    │
│  │                            │    │
│  │   OS Cluster: 10.10.2.10   │    │
│  │   - K3s (Backend Pods)     │    │
│  └────────────────────────────┘    │
│                                    │
└────────────────────────────────────┘
```

## Components

### Auth Portal (172.10.10.170)
- **Login UI**: Port 80 - Static HTML login page
- **JWT Server**: Port 8888 - Issues HS256 signed tokens (15-minute expiry)
- **WireGuard Hub**: 10.99.0.100 - Central tunnel endpoint
- Redirects authenticated users to AWS Gateway

### Identity Server (10.40.1.20)
- **SPIRE Server**: Port 8081
- Trust domain: `zta.local`
- Issues X.509 SVIDs with 5-minute TTL
- Auto-rotation of workload certificates

### AWS Gateway (10.20.2.5)
- **OPA**: Port 9191 (gRPC), 8181 (HTTP)
- **Envoy**: Port 8080 - JWT validation + routing
- **SPIRE Agent**: Fetches SVID for mTLS client
- **WireGuard Spoke**: 10.99.0.1
- Workload ID: `spiffe://zta.local/workload/aws-service`

### OS Gateway (10.10.2.5)
- **Envoy mTLS**: Port 443 - Terminates mTLS from AWS
- **SPIRE Agent**: Fetches SVID for mTLS server
- **WireGuard Spoke**: 10.99.0.2
- Workload ID: `spiffe://zta.local/workload/os-service`

### Kubernetes Clusters
- **AWS Cluster (10.20.2.10)**: K3s running UI Pods on port 30080
- **OS Cluster (10.10.2.10)**: K3s running Backend API Pods on port 30081

## Security Flow

### Authentication Flow
```
User → Auth Portal → JWT Token (15-minute TTL)
```

### Request Flow with Authorization
```
1. User sends request with JWT to Auth Portal
2. Auth Portal forwards to AWS Gateway via WireGuard (10.99.0.1:8080)
3. Envoy extracts JWT, sends to OPA for policy check
4. OPA validates JWT signature, claims, permissions
5. If allowed, Envoy routes to OS Gateway (10.99.0.2:443) with mTLS
6. OS Gateway terminates mTLS, validates client cert
7. Request forwarded to Backend Pod
8. Response returns through same path
```

### mTLS Certificate Chain
```
SPIRE CA (zta.local)
    │
    ├── AWS Gateway SVID (spiffe://zta.local/workload/aws-service)
    │   TTL: 5 minutes, auto-rotated
    │
    └── OS Gateway SVID (spiffe://zta.local/workload/os-service)
        TTL: 5 minutes, auto-rotated
```

## Network Isolation

| Source      | Destination     | Protocol      | Port     | Allowed |
|-------------|-----------------|---------------|----------|---------|
| Internet    | Auth Portal     | HTTP          | 80, 8888 |   ✅    |
| Internet    | AWS/OS Networks | Any           | Any      |   ❌    |
| Auth Portal | AWS Gateway     | UDP/WireGuard | 51820    |   ✅    |
| AWS Gateway | OS Gateway      | TCP/mTLS      | 443      |   ✅    |
| AWS Gateway | SPIRE Server    | TCP           | 8081     |   ✅    |
| OS Gateway  | SPIRE Server    | TCP           | 8081     |   ✅    |

## IP Addressing Summary

| Network       | CIDR         | Router               |
|---------------|--------------|----------------------|
| DMZ           | 10.50.1.0/24 | router-dmz           |
| Observability | 10.40.1.0/24 | router-observability |
| Cloud AWS     | 10.20.2.0/24 | router-dmz           |
| Cloud OS      | 10.10.2.0/24 | router-dmz           |
| WireGuard     | 10.99.0.0/24 | (overlay)            |

## Floating IPs (Zero Trust Model)

> ⚠️ **Zero Trust**: ONLY Auth Portal has a public floating IP. All other services are accessed via Auth Portal (SSH tunnels or reverse proxy).

| VM             | Internal IP | Public IP        | Access Method              |
|----------------|-------------|:----------------:|----------------------------|
| vm-auth-portal | 10.50.1.10  | ✅ 172.10.10.170 | Direct                     |
| vm-monitoring  | 10.40.1.10  |        ❌        | SSH tunnel via Auth Portal |
| vm-identity    | 10.40.1.20  |        ❌        | SSH ProxyCommand           |
| vm-aws-gateway | 10.20.2.5   |        ❌        | SSH ProxyCommand           |
| vm-os-gateway  | 10.10.2.5   |        ❌        | SSH ProxyCommand           |

### Accessing Monitoring (Grafana/Prometheus/Jaeger)

```bash
# SSH tunnel for Grafana (no public IP)
ssh -L 3000:10.40.1.10:3000 ubuntu@172.10.10.170
# Open: http://localhost:3000

# SSH tunnel for Prometheus
ssh -L 9090:10.40.1.10:9090 ubuntu@172.10.10.170
# Open: http://localhost:9090

# SSH tunnel for Jaeger
ssh -L 16686:10.40.1.10:16686 ubuntu@172.10.10.170
# Open: http://localhost:16686
```
