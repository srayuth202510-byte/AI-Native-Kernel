#!/usr/bin/env bash
set -euo pipefail

KERNEL_RELEASE="$(uname -r)"
PACKAGES=(
    "clang"
    "llvm"
    "libclang-dev"
    "bpftool"
    "linux-headers-${KERNEL_RELEASE}"
)

DRY_RUN=0
RUN_CHECK=1

print_manual_install_guidance() {
    cat <<EOF >&2
Manual remediation:
  1. Provide these tools from the host OS or a dedicated build environment:
     ${PACKAGES[*]}
  2. Ensure the running kernel headers match: ${KERNEL_RELEASE}
  3. Re-run: scripts/check-ebpf-prereqs.sh
EOF
}

print_ubuntu_core_guidance() {
    cat <<EOF >&2
Ubuntu Core detected: ${PRETTY_NAME:-unknown}

This installer only supports apt-based package installation, but Ubuntu Core does not
provide apt-get in the base system. Real eBPF/LSM prerequisites must be installed from
outside this environment, for example:
  - a classic Ubuntu/Debian host shell with apt-get
  - a dedicated build container/chroot with the required packages
  - a manually provisioned toolchain that exposes clang, llvm, and bpftool in PATH

Required packages/tools:
  ${PACKAGES[*]}

After provisioning them, re-run:
  scripts/check-ebpf-prereqs.sh
EOF
}

print_help() {
    cat <<EOF
Install real eBPF/LSM build dependencies for AI-Native Kernel.

Usage:
  $(basename "$0") [--dry-run] [--skip-check]

Options:
  --dry-run    Print the apt commands without executing them
  --skip-check Skip running scripts/check-ebpf-prereqs.sh after install
  -h, --help   Show this help text

Packages:
  ${PACKAGES[*]}
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=1
            ;;
        --skip-check)
            RUN_CHECK=0
            ;;
        -h|--help)
            print_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            print_help >&2
            exit 2
            ;;
    esac
    shift
done

if [[ ! -f /etc/os-release ]]; then
    echo "Cannot detect Linux distribution: /etc/os-release is missing" >&2
    exit 1
fi

# shellcheck disable=SC1091
source /etc/os-release

DISTRO_ID="${ID:-}"
DISTRO_LIKE="${ID_LIKE:-}"

if [[ "$DISTRO_ID" == "ubuntu-core" ]]; then
    print_ubuntu_core_guidance
    exit 1
fi

if [[ "$DISTRO_ID" != "ubuntu" && "$DISTRO_ID" != "debian" && "$DISTRO_ID" != ubuntu-* && "$DISTRO_LIKE" != *"ubuntu"* && "$DISTRO_LIKE" != *"debian"* ]]; then
    echo "Unsupported distribution for this installer: ${PRETTY_NAME:-unknown}" >&2
    print_manual_install_guidance
    exit 1
fi

if [[ "$(id -u)" -eq 0 ]]; then
    SUDO=()
elif command -v sudo >/dev/null 2>&1; then
    SUDO=("sudo")
elif [[ "$DRY_RUN" -eq 1 ]]; then
    SUDO=("sudo")
else
    echo "Need root privileges or sudo to install packages" >&2
    exit 1
fi

APT_UPDATE_CMD=("${SUDO[@]}" apt-get update)
APT_INSTALL_CMD=("${SUDO[@]}" apt-get install -y "${PACKAGES[@]}")

echo "==> AI-Native Kernel real eBPF dependency installer"
echo "    Distribution : ${PRETTY_NAME:-unknown}"
echo "    Kernel        : ${KERNEL_RELEASE}"
echo "    Packages      : ${PACKAGES[*]}"

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo
    echo "Dry run only. Commands:"
    printf '  %q' "${APT_UPDATE_CMD[@]}"
    printf '\n'
    printf '  %q' "${APT_INSTALL_CMD[@]}"
    printf '\n'
    if [[ "$RUN_CHECK" -eq 1 ]]; then
        echo "  bash scripts/check-ebpf-prereqs.sh"
    fi
    exit 0
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "apt-get is not available on this system" >&2
    print_manual_install_guidance
    exit 1
fi

echo
echo "==> Updating apt package index..."
"${APT_UPDATE_CMD[@]}"

echo
echo "==> Installing dependencies..."
"${APT_INSTALL_CMD[@]}"

if [[ "$RUN_CHECK" -eq 1 ]]; then
    echo
    echo "==> Re-checking real eBPF prerequisites..."
    bash scripts/check-ebpf-prereqs.sh
fi
