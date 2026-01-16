# Zero Trust Architecture - Technical Documentation

## System Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────────────────────────────┐
│                       ZERO TRUST MULTI-CLOUD ARCHITECTURE                                   │
│                          (Single Entry Point Design)                                        │
├────────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                             │
│                                    ┌─────────────┐                                         │
│                                    │  INTERNET   │                                         │
│                                    │   (Users)   │                                         │
│                                    └──────┬──────┘                                         │
│                                           │                                                │
│                                           │ ALL external traffic                           │
│                                           │ enters through ONE point                       │
│                                           ▼                                                │
│  ╔═════════════════════════════════════════════════════════════════════════════════════╗  │
│  ║            AWS GATEWAY - SINGLE PUBLIC ENTRY POINT (172.10.10.181)                  ║  │
│  ╠═════════════════════════════════════════════════════════════════════════════════════╣  │
│  ║                                                                                      ║  │
│  ║    ┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐  ║  │
│  ║    │    ENVOY     │────►│   KEYCLOAK   │────►│     OPA      │────►│   WIREGUARD  │  ║  │
│  ║    │   PROXY      │     │   (via       │     │   POLICY     │     │   TUNNEL     │  ║  │
│  ║    │   :80/:8080  │     │   tunnel)    │     │   :8181      │     │   :51820     │  ║  │
│  ║    │              │     │              │     │              │     │              │  ║  │
│  ║    │ • TLS Term   │     │ • JWT Issue  │     │ • Rego Rules │     │ • mTLS       │  ║  │
│  ║    │ • Routing    │     │ • AuthN      │     │ • Real-time  │     │ • Encryption │  ║  │
│  ║    │ • JWT Valid  │     │ • Token Mgmt │     │ • Audit Log  │     │ • Isolation  │  ║  │
│  ║    └──────────────┘     └──────────────┘     └──────────────┘     └───────┬──────┘  ║  │
│  ║                                                                            │         ║  │
│  ╚════════════════════════════════════════════════════════════════════════════╪═════════╝  │
│                                                                                │            │
│  ════════════════════════════════ INTERNAL NETWORK ════════════════════════════            │
│                              (No Direct Internet Access)                       │            │
│                                                                                │            │
│    ┌───────────────────────┐    ┌────────────────────────┐    ┌────────────────┴──────┐   │
│    │                       │    │                        │    │                       │   │
│    │    AWS CLOUD VPC      │    │   MANAGEMENT VPC       │    │   OPENSTACK CLOUD VPC │   │
│    │    10.20.2.0/24       │    │   10.30.1.0/24         │    │   10.10.2.0/24        │   │
│    │                       │    │                        │    │                       │   │
│    │  ┌─────────────────┐  │    │  ┌──────────────────┐  │    │  ┌─────────────────┐  │   │
│    │  │   K3s CLUSTER   │  │    │  │    KEYCLOAK      │  │    │  │   OS GATEWAY    │  │   │
│    │  │   (Frontend)    │  │    │  │    (Identity)    │  │    │  │   (mTLS :443)   │  │   │
│    │  │                 │  │    │  │    :8080         │  │    │  │                 │  │   │
│    │  │  ┌───────────┐  │  │    │  └──────────────────┘  │    │  │  ┌───────────┐  │  │   │
│    │  │  │  nginx    │  │  │    │  ┌──────────────────┐  │    │  │  │  Envoy    │  │  │   │
│    │  │  │  :30090   │  │  │    │  │   SPIRE SERVER   │  │    │  │  │  +mTLS    │  │  │   │
│    │  │  └───────────┘  │  │    │  │   :8081          │  │    │  │  └─────┬─────┘  │  │   │
│    │  │                 │  │    │  └──────────────────┘  │    │  │        │        │  │   │
│    │  └─────────────────┘  │    │  ┌──────────────────┐  │    │  │  ┌─────▼─────┐  │  │   │
│    │                       │    │  │   MONITORING     │  │    │  │  │  K3s      │  │  │   │
│    │                       │    │  │   • Prometheus   │  │    │  │  │  Backend  │  │  │   │
│    │                       │    │  │   • Grafana      │  │    │  │  │  :30091   │  │  │   │
│    │                       │    │  │   • Loki         │  │    │  │  │  (Flask)  │  │  │   │
│    │                       │    │  │   • Jaeger       │  │    │  │  └───────────┘  │  │   │
│    │                       │    │  └──────────────────┘  │    │  │                 │  │   │
│    └───────────────────────┘    └────────────────────────┘    │  └─────────────────┘  │   │
│                                                                │                       │   │
│                                                                └───────────────────────┘   │
│                                                                                             │
├────────────────────────────────────────────────────────────────────────────────────────────┤
│                                     REQUEST FLOW                                            │
│  ┌──────┐    ┌────────────┐    ┌────────┐    ┌─────┐    ┌────────────┐    ┌─────────────┐ │
│  │ User │───►│ AWS Envoy  │───►│Keycloak│───►│ OPA │───►│ WireGuard  │───►│ OS Gateway  │ │
│  │      │    │ (JWT+Route)│    │ (AuthN)│    │(Authz)   │  (mTLS)    │    │ → Backend   │ │
│  └──────┘    └────────────┘    └────────┘    └─────┘    └────────────┘    └─────────────┘ │
│                                                                                             │
└────────────────────────────────────────────────────────────────────────────────────────────┘
```

## Request Flow

### Authentication Flow

```
┌────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  User  │────►│ AWS Gateway  │────►│   Keycloak   │────►│ Return JWT   │
│Browser │     │ /auth/token  │     │  Validate    │     │   Token      │
└────────┘     └──────────────┘     └──────────────┘     └──────────────┘
    │                                                           │
    └───────────────────── Store in localStorage ◄──────────────┘
```

### Data Access Flow

```
┌────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  User  │────►│ AWS Envoy    │────►│     OPA      │────►│  OS Envoy    │
│+JWT    │     │ JWT Validate │     │ Policy Check │     │ mTLS Verify  │
└────────┘     └──────────────┘     └──────────────┘     └──────┬───────┘
                                                                │
┌────────┐     ┌──────────────┐     ┌──────────────┐            │
│Response│◄────│ AWS Envoy    │◄────│  OS Envoy    │◄───────────┘
│  JSON  │     │   Return     │     │  Forward     │     Backend API
└────────┘     └──────────────┘     └──────────────┘     :30091
```

## Component Configuration

### Envoy Proxy (AWS Gateway)

- **Listen**: `:8080` (redirected from `:80` via iptables)
- **Network Mode**: Host (for iptables NAT)
- **JWT Provider**: Keycloak (`/realms/zta`)
- **Upstream Clusters**:
  - `local_frontend` → K3s :30090
  - `os_gateway_backend` → 10.99.0.2:443 (mTLS)
  - `keycloak_cluster` → localhost:8888

### Envoy Proxy (OS Gateway)

- **Listen**: `:443` (TLS)
- **TLS Mode**: mTLS (require client certificate)
- **Upstream Clusters**:
  - `backend_k3s_cluster` → 10.10.2.10:30091

### OPA Policies

```rego
# Allow public paths
allow if { http_request.path == "/" }
allow if { startswith(http_request.path, "/auth/") }

# Require auth for API
allow if {
    startswith(http_request.path, "/api/")
    is_valid_token
}
```

### WireGuard Configuration

```ini
# AWS Gateway (10.99.0.1)
[Interface]
Address = 10.99.0.1/24
ListenPort = 51820

[Peer]
AllowedIPs = 10.99.0.2/32, 10.10.2.0/24
Endpoint = <OS_GATEWAY_PUBLIC_IP>:51820
```

## Security Considerations

1. **Token Lifetime**: 15 minutes (configurable in .env)
2. **Certificate Rotation**: Manual (SPIRE auto-rotates SVID every 5 min)
3. **Network Isolation**: Each cloud in separate VPC
4. **Secrets Management**: Use .env file (not committed to git)

## Performance Benchmarks

| Metric | Measured Value | Target |
|--------|---------------|--------|
| Auth Latency | ~50ms | <500ms |
| E2E Latency | ~15ms | <100ms |
| Tunnel Latency | ~0.6ms | <10ms |
| Throughput | ~20 req/s | >10 req/s |
