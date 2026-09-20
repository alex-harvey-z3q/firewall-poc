terraform {
  required_version = ">= 1.6, < 2.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }
}
provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}
variable "subscription_id" { type = string }
variable "location" {
  type    = string
  default = "australiaeast"
}
variable "prefix" {
  type    = string
  default = "host-fw-poc"
}
variable "image_id" {
  description = "Prepared, generalized Ubuntu 24.04 image with Puppet 8, pinned modules and pre-network quarantine. No stock marketplace image."
  type        = string
}
variable "ssh_public_key" { type = string }
variable "ipam_file" {
  description = "Path to validated external IPAM snapshot; relative to this directory."
  type        = string
  default     = "../config/ipam.json"
}
variable "vm_size" {
  type    = string
  default = "Standard_B1s"
}
locals {
  inventory = jsondecode(file("${path.module}/../config/inventory.json"))
  policy    = jsondecode(file("${path.module}/../config/policy.json"))
  ipam      = jsondecode(file(var.ipam_file))
}
resource "azurerm_resource_group" "this" {
  name     = var.prefix
  location = var.location
}
resource "azurerm_virtual_network" "this" {
  name                = "${var.prefix}-vnet"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = [local.inventory.network]
}
resource "azurerm_subnet" "tier" {
  for_each                        = local.inventory.subnets
  name                            = each.key
  resource_group_name             = azurerm_resource_group.this.name
  virtual_network_name            = azurerm_virtual_network.this.name
  address_prefixes                = [each.value]
  default_outbound_access_enabled = false
}
resource "azurerm_network_interface" "node" {
  for_each            = local.inventory.nodes
  name                = "${var.prefix}-${replace(each.key, "_", "-")}-nic"
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.tier[each.value.tier].id
    private_ip_address_allocation = "Static"
    private_ip_address            = each.value.ip
  }
}
resource "azurerm_linux_virtual_machine" "node" {
  for_each                        = local.inventory.nodes
  name                            = "${var.prefix}-${replace(each.key, "_", "-")}"
  computer_name                   = replace(each.key, "_", "-")
  resource_group_name             = azurerm_resource_group.this.name
  location                        = var.location
  size                            = var.vm_size
  admin_username                  = "fwadmin"
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.node[each.key].id]
  source_image_id                 = var.image_id
  provision_vm_agent              = true
  admin_ssh_key {
    username   = "fwadmin"
    public_key = var.ssh_public_key
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }
  custom_data = base64encode("#cloud-config\n${yamlencode({
    write_files = [{
      path        = "/etc/firewall-poc/bundle.json"
      permissions = "0600"
      owner       = "root:root"
      content = jsonencode({
        node      = each.key
        inventory = local.inventory
        policy    = local.policy
        ipam      = local.ipam
      })
    }]
    runcmd = [["systemctl", "start", "--no-block", "firewall-apply.service"]]
  })}")
  boot_diagnostics {}
  tags = { application = each.value.app, tier = each.value.tier }
  lifecycle {
    precondition {
      condition     = timecmp(local.ipam.expires_at, plantimestamp()) > 0
      error_message = "IPAM snapshot is expired. Fetch a fresh, reviewed snapshot."
    }
    precondition {
      condition     = length(base64encode(jsonencode({ inventory = local.inventory, policy = local.policy, ipam = local.ipam }))) < 60000
      error_message = "Bootstrap bundle exceeds safe custom-data size. Reduce IPAM memberships."
    }
  }
}
output "nodes" {
  value = { for name, nic in azurerm_network_interface.node : name => nic.private_ip_address }
}
output "resource_group" { value = azurerm_resource_group.this.name }
