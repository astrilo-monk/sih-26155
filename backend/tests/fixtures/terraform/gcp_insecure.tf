# Written for NetAuditAI tests: GCP firewall rules open to the internet
resource "google_compute_firewall" "ssh" {
  name          = "allow-ssh"
  network       = "default"
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "all" {
  name          = "allow-all"
  network       = "default"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "all"
  }
}
