variable "name_prefix" {
  description = "Prefix applied to resource names (e.g. \"agcms-prod\")."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
}

variable "availability_zones" {
  description = "AZs to spread subnets across. Leave empty to auto-select first 3 in region."
  type        = list(string)
  default     = []
}
