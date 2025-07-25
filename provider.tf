terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.18.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
  backend "s3" {
    bucket = "tf-tuts-state-2025"
    key    = "state"
    region = "us-east-1"
  }
}

# Provider AWS
provider "aws" {
  region = "us-east-1"
}

# Provider Google Cloud
provider "google" {
  project = "progettocloud-467013"
  region  = "us-central1"
  zone    = "us-central1-a"
}