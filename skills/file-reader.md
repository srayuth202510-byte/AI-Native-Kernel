+++
name = "file-reader"
description = "read files under /srv/ank-demo only — no network, no exec beyond launch"

[capabilities]
scope_paths = ["/srv/ank-demo"]
allow = ["file", "exec"]
+++
Read and report on files under /srv/ank-demo. The kernel confines file_open
to that directory (plus the read-only system prefixes ank-run adds so the
binary itself can load); everything else — /home, /etc/shadow, other
projects — is denied, and no socket can be created.
