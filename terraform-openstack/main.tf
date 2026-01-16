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

# --- Zone 1: Management ---
resource "openstack_networking_network_v2" "management" {
  name           = "net-management"
  admin_state_up = true
}

resource "openstack_networking_subnet_v2" "management" {
  name            = "subnet-management"
  network_id      = openstack_networking_network_v2.management.id
  cidr            = "10.30.1.0/24"
  ip_version      = 4
  dns_nameservers = ["8.8.8.8", "8.8.4.4"]
}

# --- Zone 2: Observability ---
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

#################### ROUTERS ####################

resource "openstack_networking_router_v2" "aws" {
  name                = "router-aws"
  external_network_id = data.openstack_networking_network_v2.external.id
}
resource "openstack_networking_router_interface_v2" "cloud_aws" {
  router_id = openstack_networking_router_v2.aws.id
  subnet_id = openstack_networking_subnet_v2.cloud_aws.id
}

resource "openstack_networking_router_v2" "os" {
  name                = "router-os"
  external_network_id = data.openstack_networking_network_v2.external.id
}
resource "openstack_networking_router_interface_v2" "cloud_os" {
  router_id = openstack_networking_router_v2.os.id
  subnet_id = openstack_networking_subnet_v2.cloud_os.id
}

resource "openstack_networking_router_v2" "mgmt" {
  name                = "router-mgmt"
  external_network_id = data.openstack_networking_network_v2.external.id
}
resource "openstack_networking_router_interface_v2" "management" {
  router_id = openstack_networking_router_v2.mgmt.id
  subnet_id = openstack_networking_subnet_v2.management.id
}
resource "openstack_networking_router_interface_v2" "observability" {
  router_id = openstack_networking_router_v2.mgmt.id
  subnet_id = openstack_networking_subnet_v2.observability.id
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

#################### FLOATING IPS ####################

resource "openstack_networking_floatingip_v2" "aws_gateway" {
  pool = var.external_network_name
}

resource "openstack_networking_floatingip_v2" "os_gateway" {
  pool = var.external_network_name
}

resource "openstack_networking_floatingip_v2" "monitoring" {
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

# Associate Floating IP to Port (Not Instance) -> More Reliable
resource "openstack_networking_floatingip_associate_v2" "aws_gateway" {
  floating_ip = openstack_networking_floatingip_v2.aws_gateway.address
  port_id     = openstack_networking_port_v2.port_aws_gateway.id
}

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

resource "openstack_networking_floatingip_associate_v2" "os_gateway" {
  floating_ip = openstack_networking_floatingip_v2.os_gateway.address
  port_id     = openstack_networking_port_v2.port_os_gateway.id
}

# 3. Monitoring VM (Uses Pre-created Port, Flavor Nano-Plus for DISK)
resource "openstack_compute_instance_v2" "monitoring" {
  name            = "vm-monitoring"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.flavor_app  # <--- Dùng 15GB Disk
  key_pair        = var.keypair_name

  network {
    port = openstack_networking_port_v2.port_monitoring.id
  }
}

resource "openstack_networking_floatingip_associate_v2" "monitoring" {
  floating_ip = openstack_networking_floatingip_v2.monitoring.address
  port_id     = openstack_networking_port_v2.port_monitoring.id
}

# 4. Identity VM (Flavor Nano-Plus for DISK)
resource "openstack_compute_instance_v2" "identity" {
  name            = "vm-identity"
  image_id        = data.openstack_images_image_v2.ubuntu.id
  flavor_name     = var.flavor_app  # <--- Dùng 15GB Disk
  key_pair        = var.keypair_name
  security_groups = ["sg-zta"]

  network {
    uuid        = openstack_networking_network_v2.management.id
    fixed_ip_v4 = "10.30.1.20"
  }
  depends_on = [openstack_networking_subnet_v2.management]
}

# 5. AWS Master (Flavor Nano-Plus for DISK)
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

# 6. OS Master (Flavor Nano-Plus for DISK)
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

output "aws_gateway_ip" {
  value = openstack_networking_floatingip_v2.aws_gateway.address
}

output "os_gateway_ip" {
  value = openstack_networking_floatingip_v2.os_gateway.address
}

output "monitoring_ip" {
  value = openstack_networking_floatingip_v2.monitoring.address
}
