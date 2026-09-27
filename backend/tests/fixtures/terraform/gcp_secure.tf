# Written for NetAuditAI tests: SSH only through Identity-Aware Proxy
resource "google_compute_firewall" "ssh" {
  name          = "allow-ssh-iap"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
