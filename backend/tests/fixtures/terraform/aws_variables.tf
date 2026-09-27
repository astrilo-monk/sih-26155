# Written for NetAuditAI tests: the sources come from variables the file does not resolve
variable "admin_cidr" {
  type = string
}

resource "aws_security_group" "bastion" {
  name = "bastion-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
}

resource "aws_vpc_security_group_ingress_rule" "all" {
  security_group_id = aws_security_group.bastion.id
  cidr_ipv4         = "${var.office_prefix}/32"
  ip_protocol       = "-1"
}
