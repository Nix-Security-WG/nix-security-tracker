terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.45"
    }
  }

  backend "s3" {
    bucket                      = "stf-tf-state"
    key                         = "terraform.tfstate"
    endpoint                    = "nbg1.your-objectstorage.com"
    region                      = "nbg1"
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_metadata_api_check     = true
    force_path_style            = true
  }
}

variable "hcloud_token" {
  sensitive = true
}

provider "hcloud" {
  token = var.hcloud_token
}

resource "hcloud_server" "stfmaster" {
  name        = "security-tracker-1"
  image       = "debian-12"
  server_type = "cpx41"
  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }
  datacenter = "nbg1-dc3"
  labels = {
    "Managed-by" : "Terraform"
  }
  delete_protection  = true
  rebuild_protection = true
}
