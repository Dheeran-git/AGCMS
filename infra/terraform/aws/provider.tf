provider "aws" {
  region = var.region

  default_tags {
    tags = merge(
      {
        Project     = var.project
        Environment = var.environment
        ManagedBy   = "terraform"
        Component   = "agcms-platform"
      },
      var.tags,
    )
  }
}
