# Demo: an AWS security group in Terraform, written for NetAuditAI
resource "aws_security_group" "bastion" {
  name   = "bastion-sg"
  vpc_id = "vpc-0a1b2c3d"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
