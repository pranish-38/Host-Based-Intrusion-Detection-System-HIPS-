{
    "monitored_paths": [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh",
        "/home"
    ],
    "suspicious_processes": [
        "nc",
        "ncat",
        "netcat",
        "reverse_shell",
        "mimikatz",
        "john",
        "hydra",
        "nmap",
        "metasploit",
        "nikto",
        "sqlmap"
    ],
    "blocked_ports": [
        4444,
        5555,
        6666,
        31337,
        12345
    ],
    "whitelist_ips": [
        "127.0.0.1",
        "::1"
    ],
    "max_cpu_percent": 90,
    "max_memory_percent": 80,
    "alert_mode": "log"
}
