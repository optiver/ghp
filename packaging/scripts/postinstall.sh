#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    # Units ship disabled by default: ghp is more commonly deployed as a
    # client than a server, and an enabled socket unit would implicitly bind
    # ports 80/443 on install. The system admin must opt in explicitly:
    #   systemctl enable --now ghp.socket
fi
