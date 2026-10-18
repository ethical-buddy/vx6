# Security and limitations

VX6 currently provides signed node and service records, encrypted node sessions, and relay-based hidden-service paths. It does not claim full traffic-analysis resistance or Tor-equivalent anonymity.

The current production transport is TCP. QUIC is not activated as a production transport. Hidden-stream failover, adversarial DHT resistance, and the eBPF/XDP relay path remain areas of work. Use VX6 for controlled testing and deployments whose threat model matches these limits.

See [`internal/threat-model/threat_model.md`](internal/threat-model/threat_model.md) for the detailed threat model.
