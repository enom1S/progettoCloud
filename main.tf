resource "aws_instance" "my_vm" {
  ami           = var.ami //Ubuntu AMI
  instance_type = var.instance_type

  tags = {
    Name = var.name_tag,
  }
}

resource "google_compute_instance" "my_gcp_vm" {
  name         = "my-gcp-instance"
  machine_type = "e2-micro" # equivalente a t2.micro di AWS
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts" # Ubuntu 22.04 LTS
    }
  }

  network_interface {
    network = "default"
    access_config {
      # Questo darà un IP pubblico alla VM
    }
  }

  tags = ["terraform-managed"]
}

# Output per vedere gli IP delle VM
output "aws_instance_ip" {
  value = aws_instance.my_vm.public_ip
}

output "gcp_instance_ip" {
  value = google_compute_instance.my_gcp_vm.network_interface[0].access_config[0].nat_ip
}

resource "aws_s3_bucket" "state_bucket" {
 bucket = "tf-tuts-state-2025"

 tags = {
   Name = "State Bucket"
 }
}