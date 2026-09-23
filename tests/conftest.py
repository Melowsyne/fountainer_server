# Copyright (c) 2026 Melowsyne Unipessoal Lda. All rights reserved.
#
# This source code is proprietary. No license is granted to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies of
# this software without prior written permission from the copyright holder.
#
# For licensing inquiries, contact: info@melowsyne.com

"""Test setup: put the linux_server root on the import path + helpers."""
import socket
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def free_port() -> int:
    """Determine a free TCP port (best-effort, for local test servers)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port
