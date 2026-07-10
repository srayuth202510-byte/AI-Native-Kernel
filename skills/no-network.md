+++
name = "no-network"
description = "run a command with file and exec access but no network at all"

[capabilities]
allow = ["file", "exec"]
+++
Run the given command normally, but the kernel denies every socket_create —
DNS lookups and outbound connections fail no matter what the process tries.
