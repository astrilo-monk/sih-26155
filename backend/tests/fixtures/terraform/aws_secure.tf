# Written for NetAuditAI tests: SSH only from the admin network
provider "aws" {
  region = "eu-west-1"
}

resource "aws_security_group" "bastion" {
  name   = "bastion-sg"
  vpc_id = "vpc-0a1b2c3d"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

resource "aws_security_group_rule" "https" {
  type              = "ingress"
  security_group_id = aws_security_group.bastion.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["192.0.2.0/24"]
}
