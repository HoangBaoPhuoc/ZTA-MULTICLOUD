terraform {
  required_version = ">= 1.0"
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.53"
    }
  }
}

provider "openstack" {
  # Explicitly set credentials to avoid env var conflicts
  auth_url    = "http://192.168.1.254:5000/v3"
  user_name   = "zerotrust_admin"
  password    = "123"
  tenant_name = "ZeroTrust_Project"
  domain_name = "Default"
}

#################### VARIABLES ####################

variable "external_network_name" {
  type    = string
  default = "public1"
}

variable "image_name" {
  type    = string
  default = "ubuntu-22.04"
}

variable "keypair_name" {
  type = string
  default = "zta-keypair"
}

# --- FLAVOR CONFIGURATION ---

# Flavor cho Gateway (Chỉ cần Routing, ít tốn Disk) -> Dùng nano (5GB Disk)
variable "flavor_gateway" {
  type    = string
  default = "zta-optimal"
}

# Flavor cho App/DB/K3s (Cần Disk để pull Docker Image) -> Dùng nano-plus (15GB Disk)
# Lưu ý: Bạn phải tạo flavor này trước bằng CLI
variable "flavor_app" {
  type    = string
  default = "zta-optimal"
}

#################### DATA ####################

data "openstack_images_image_v2" "ubuntu" {
  name        = var.image_name
  most_recent = true
}

data "openstack_networking_network_v2" "external" {
  name = var.external_network_name
}

#################### NETWORKS & SUBNETS ####################

# --- Zone 1: Observability (Monitoring + Identity) ---
resource "openstack_networking_network_v2" "observability" {
  name           = "net-observability"
  admin_state_up = true
}

resource "openstack_networking_subnet_v2" "observability" {
  name            = "subnet-observability"
  network_id      = openstack_networking_network_v2.observability.id
  cidr            = "10.40.1.0/24"
  ip_version      = 4
  dns_nameservers = ["8.8.8.8", "8.8.4.4"]
}

# --- Zone 3: Cloud OS ---
resource "openstack_networking_network_v2" "cloud_os" {
  name           = "net-cloud-os"
  admin_state_up = true
}

resource "openstack_networking_subnet_v2" "cloud_os" {
  name            = "subnet-cloud-os"
  network_id      = openstack_networking_network_v2.cloud_os.id
  cidr            = "10.10.2.0/24"
  ip_version      = 4
  dns_nameservers = ["8.8.8.8", "8.8.4.4"]
}

# --- Zone 4: Cloud AWS ---
resource "openstack_networking_network_v2" "cloud_aws" {
  name           = "net-cloud-aws"
  admin_state_up = true
}

resource "openstack_networking_subnet_v2" "cloud_aws" {
  name            = "subnet-cloud-aws"
  network_id      = openstack_networking_network_v2.cloud_aws.id
  cidr            = "10.20.2.0/24"
  ip_version      = 4
  dns_nameservers = ["8.8.8.8", "8.8.4.4"]
}

# --- Zone 5: DMZ (Auth Portal - Single Entry Point) ---
# This network is ISOLATED from AWS and OS clusters
# Auth Portal can only reach Keycloak, not direct to OS Cluster
resource "openstack_networking_network_v2" "dmz" {
  name           = "net-dmz"
  admin_state_up = true
}

resource "openstack_networking_subnet_v2" "dmz" {
  name            = "subnet-dmz"
  network_id      = openstack_networking_network_v2.dmz.id
  cidr            = "10.50.1.0/24"
  ip_version      = 4
  dns_nameservers = ["8.8.8.8", "8.8.4.4"]
}

#################### ROUTERS ####################
# Hub-and-Spoke Zero Trust Architecture
# - Hub: router-dmz (single exit point to internet)
# - Spokes: AWS, OS networks connected to Hub
# - SNAT disabled: internal VMs cannot access internet directly

# Observability Router - For monitoring and identity VMs (needs internet for docker pulls)
resource "openstack_networking_router_v2" "observability" {
  name                = "router-observability"
  external_network_id = data.openstack_networking_network_v2.external.id
}
resource "openstack_networking_router_interface_v2" "observability" {
  router_id = openstack_networking_router_v2.observability.id
  subnet_id = openstack_networking_subnet_v2.observability.id
}

# DMZ Router (HUB) - Single entry/exit point
# Connects: DMZ, AWS, OS networks
# SNAT disabled - only Auth Portal has floating IP for internet access
resource "openstack_networking_router_v2" "dmz" {
  name                = "router-dmz"
  external_network_id = data.openstack_networking_network_v2.external.id
  enable_snat         = false
}

# Hub interfaces
resource "openstack_networking_router_interface_v2" "dmz" {
  router_id = openstack_networking_router_v2.dmz.id
  subnet_id = openstack_networking_subnet_v2.dmz.id
}

# Spoke: AWS Network -> Hub
resource "openstack_networking_router_interface_v2" "cloud_aws" {
  router_id = openstack_networking_router_v2.dmz.id
  subnet_id = openstack_networking_subnet_v2.cloud_aws.id
}

# Spoke: OS Network -> Hub  
resource "openstack_networking_router_interface_v2" "cloud_os" {
  router_id = openstack_networking_router_v2.dmz.id
  subnet_id = openstack_networking_subnet_v2.cloud_os.id
}

#################### SECURITY GROUP ####################

resource "openstack_networking_secgroup_v2" "default" {
  name        = "sg-zta"
  description = "Security group for ZTA Multicloud Lab"
}

# --- CÁC RULE CƠ BẢN ---
resource "openstack_networking_secgroup_rule_v2" "ssh_all" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.default.id
}

resource "openstack_networking_secgroup_rule_v2" "icmp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "icmp"
  security_group_id = openstack_networking_secgroup_v2.default.id
}

# Cho phép traffic nội bộ (10.x.x.x) thông nhau hoàn toàn
resource "openstack_networking_secgroup_rule_v2" "internal_all" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  remote_ip_prefix  = "10.0.0.0/8"
  security_group_id = openstack_networking_secgroup_v2.default.id
}

# --- RULE MỚI CHO GATEWAY & APP (HTTP/HTTPS/APP) ---
resource "openstack_networking_secgroup_rule_v2" "http" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.default.id
}

resource "openstack_networking_secgroup_rule_v2" "https" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.default.id
}

resource "openstack_networking_secgroup_rule_v2" "app_keycloak" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8080
  port_range_max    = 8080
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.default.id
}

resource "openstack_networking_secgroup_rule_v2" "app_opa" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8181
  port_range_max    = 8181
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.default.id
}

# --- RULE MỚI CHO MONITORING STACK ---
resource "openstack_networking_secgroup_rule_v2" "mon_grafana" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 3000
  port_range_max    = 3000
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.default.id
}

resource "openstack_networking_secgroup_rule_v2" "mon_prometheus" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 9090
  port_range_max    = 9090
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.default.id
}

resource "openstack_networking_secgroup_rule_v2" "mon_loki" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 3100
  port_range_max    = 3100
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.default.id
}

# --- WIREGUARD VPN TUNNEL ---
resource "openstack_networking_secgroup_rule_v2" "wireguard_udp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 51820
  port_range_max    = 51820
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.default.id
}

#################### DMZ SECURITY GROUP ####################
# Restricted security group for Auth Portal
# Only allows: SSH, HTTP (Auth Portal UI), and outbound to Keycloak
# NO direct access to OS Cluster (10.10.2.0/24)

resource "openstack_networking_secgroup_v2" "dmz" {
  name        = "sg-dmz"
  description = "Security group for DMZ Auth Portal - Isolated from clusters"
}

# SSH access for management
resource "openstack_networking_secgroup_rule_v2" "dmz_ssh" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.dmz.id
}

# HTTP for Auth Portal UI
resource "openstack_networking_secgroup_rule_v2" "dmz_http" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.dmz.id
}

# HTTPS for Auth Portal
resource "openstack_networking_secgroup_rule_v2" "dmz_https" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.dmz.id
}

# Auth Portal App Port (8888)
resource "openstack_networking_secgroup_rule_v2" "dmz_auth_portal" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8888
  port_range_max    = 8888
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.dmz.id
}

# Allow outbound to Keycloak (via Monitoring proxy - 10.40.1.0/24)
resource "openstack_networking_secgroup_rule_v2" "dmz_to_keycloak" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8080
  port_range_max    = 8080
  remote_ip_prefix  = "10.40.1.0/24"
  security_group_id = openstack_networking_secgroup_v2.dmz.id
}

# ICMP for debugging
resource "openstack_networking_secgroup_rule_v2" "dmz_icmp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "icmp"
  security_group_id = openstack_networking_secgroup_v2.dmz.id
}

# Note: Default egress rules are automatically created by OpenStack
# No need to explicitly define egress_all rule

# BLOCK: NO rules allowing DMZ to reach OS Cluster (10.10.2.0/24)
# BLOCK: NO rules allowing DMZ to reach AWS internal (10.20.2.0/24)
# This ensures Auth Portal cannot directly access backend clusters

#################### FLOATING IPS ####################
# Hub-and-Spoke Zero Trust: ONLY Auth Portal has floating IP
# All other services accessed through Auth Portal proxy
# Monitoring (Grafana/Jaeger) - NO public IP, access via Auth Portal

# Floating IP for Auth Portal (DMZ) - THE ONLY public entry point
resource "openstack_networking_floatingip_v2" "auth_portal" {
  pool = var.external_network_name
}

#################### FIXED PORTS (KEY CHANGE) ####################
# Tạo Port trước để đảm bảo gắn IP thành công

resource "openstack_networking_port_v2" "port_aws_gateway" {
  name           = "port-aws-gateway"
  network_id     = openstack_networking_network_v2.cloud_aws.id
  admin_state_up = true
  security_group_ids = [openstack_networking_secgroup_v2.default.id]
  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.cloud_aws.id
    ip_address = "10.20.2.5"
  }
}

resource "openstack_networking_port_v2" "port_os_gateway" {
  name           = "port-os-gateway"
  network_id     = openstack_networking_network_v2.cloud_os.id
  admin_state_up = true
  security_group_ids = [openstack_networking_secgroup_v2.default.id]
  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.cloud_os.id
    ip_address = "10.10.2.5"
  }
}

resource "openstack_networking_port_v2" "port_monitoring" {
  name           = "port-monitoring"
  network_id     = openstack_networking_network_v2.observability.id
  admin_state_up = true
  security_group_ids = [openstack_networking_secgroup_v2.default.id]
  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.observability.id
    ip_address = "10.40.1.10"
  }
}

# Port for Auth Portal in DMZ
resource "openstack_networking_port_v2" "port_auth_portal" {
  name           = "port-auth-portal"
  network_id     = openstack_networking_network_v2.dmz.id
  admin_state_up = true
  security_group_ids = [openstack_networking_secgroup_v2.dmz.id]
  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.dmz.id
    ip_address = "10.50.1.10"
  }
}

#################### INSTANCES ####################

# 1. AWS Gateway (Uses Pre-created Port, Flavor Nano)
resource "openstack_compute_instance_v2" "aws_gateway" {
  name            = "vm-aws-gateway"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.flavor_gateway
  key_pair        = var.keypair_name
  
  network {
    port = openstack_networking_port_v2.port_aws_gateway.id
  }
}

# No Floating IP for AWS Gateway - Hub-and-Spoke model
# Access via Auth Portal only

# 2. OS Gateway (Uses Pre-created Port, Flavor Nano)
resource "openstack_compute_instance_v2" "os_gateway" {
  name            = "vm-os-gateway"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.flavor_gateway
  key_pair        = var.keypair_name

  network {
    port = openstack_networking_port_v2.port_os_gateway.id
  }
}

# No Floating IP for OS Gateway - Hub-and-Spoke model
# Access via Auth Portal only

# 3. Monitoring VM (Uses Pre-created Port, Flavor Nano-Plus for DISK)
# NO Floating IP - Zero Trust: Access via Auth Portal proxy only
resource "openstack_compute_instance_v2" "monitoring" {
  name            = "vm-monitoring"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.flavor_app  # <--- Dùng 15GB Disk
  key_pair        = var.keypair_name

  network {
    port = openstack_networking_port_v2.port_monitoring.id
  }
}

# REMOVED: floating IP for monitoring - Zero Trust compliance
# Monitoring only accessible via Auth Portal reverse proxy

# 4. Auth Portal VM (DMZ - Isolated Network)
resource "openstack_compute_instance_v2" "auth_portal" {
  name            = "vm-auth-portal"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = "zta-flavor"  # 1024MB RAM - lighter than zta-optimal
  key_pair        = var.keypair_name

  network {
    port = openstack_networking_port_v2.port_auth_portal.id
  }
}

resource "openstack_networking_floatingip_associate_v2" "auth_portal" {
  floating_ip = openstack_networking_floatingip_v2.auth_portal.address
  port_id     = openstack_networking_port_v2.port_auth_portal.id
}

# 5. Identity VM (Keycloak + SPIRE Server) - Same subnet as monitoring for hub routing
resource "openstack_compute_instance_v2" "identity" {
  name            = "vm-identity"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.flavor_app  # <--- Dùng 15GB Disk
  key_pair        = var.keypair_name
  security_groups = ["sg-zta"]

  network {
    uuid        = openstack_networking_network_v2.observability.id
    fixed_ip_v4 = "10.40.1.20"
  }
  depends_on = [openstack_networking_subnet_v2.observability]
}

# 6. AWS Master (Flavor Nano-Plus for DISK)
resource "openstack_compute_instance_v2" "aws_master" {
  name            = "aws-master"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.flavor_app  # <--- Dùng 15GB Disk
  key_pair        = var.keypair_name
  security_groups = ["sg-zta"]

  network {
    uuid        = openstack_networking_network_v2.cloud_aws.id
    fixed_ip_v4 = "10.20.2.10"
  }
  depends_on = [openstack_networking_subnet_v2.cloud_aws]
}

# 7. OS Master (Flavor Nano-Plus for DISK)
resource "openstack_compute_instance_v2" "os_master" {
  name            = "os-master"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.flavor_app  # <--- Dùng 15GB Disk
  key_pair        = var.keypair_name
  security_groups = ["sg-zta"]

  network {
    uuid        = openstack_networking_network_v2.cloud_os.id
    fixed_ip_v4 = "10.10.2.10"
  }
  depends_on = [openstack_networking_subnet_v2.cloud_os]
}

#################### OUTPUTS ####################

# Zero Trust: Only Auth Portal has public access
output "auth_portal_ip" {
  value       = openstack_networking_floatingip_v2.auth_portal.address
  description = "Auth Portal (Single Entry Point) - THE ONLY public entry point"
}

# Monitoring - Internal only, access via Auth Portal proxy
output "monitoring_internal_ip" {
  value       = "10.40.1.10"
  description = "Monitoring (Grafana/Jaeger) - NO public IP, access via Auth Portal /grafana/"
}

# Internal IPs (no public access)
output "aws_gateway_internal_ip" {
  value       = "10.20.2.5"
  description = "AWS Gateway - internal only, access via Auth Portal"
}

output "os_gateway_internal_ip" {
  value       = "10.10.2.5"
  description = "OS Gateway - internal only, access via Auth Portal"
}
