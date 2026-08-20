#!/usr/bin/env bash
#
# Backup for the TacticalRMM MCP server.
#
# Captures the things that are painful or impossible to recreate: the
# credentials in .env, the TLS keypair, live approval/session state, and the
# customised code. Deliberately NOT the venv - that is reproducible from
# requirements.txt and would dominate the archive.
#
# Rotation deliberately mirrors /rmm/backup.sh (daily 14d / weekly 60d /
# monthly 380d) so there is one retention scheme on this box, not two.
#
#   ./backup-mcp.sh            one-off backup into /rmmbackups/mcp/
#   ./backup-mcp.sh --auto     rotating backup, for the systemd timer
#   ./backup-mcp.sh --verify <file>   check an archive is intact and readable
#   ./backup-mcp.sh --no-logs  skip the audit log (smaller, less forensic value)
#
# If /opt/trmm-mcp/.backup-passphrase exists (mode 600), the archive is
# encrypted with GPG AES-256. Do that before copying backups anywhere else:
# an unencrypted archive contains every credential this server holds.

set -euo pipefail

SRC="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
DEST="/rmmbackups/mcp"
PASSPHRASE_FILE="${SRC}/.backup-passphrase"
STAMP="$(date +'%Y-%m-%d-%H%M%S')"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
say() { printf "${GREEN}%s${NC}\n" "$1"; }
warn() { printf "${YELLOW}%s${NC}\n" "$1"; }
die() { printf "${RED}ERROR: %s${NC}\n" "$1" >&2; exit 1; }

# ---------------------------------------------------------------- verify mode
if [ "${1:-}" = "--verify" ]; then
    archive="${2:-}"
    [ -f "$archive" ] || die "no such archive: $archive"
    if [ -f "${archive}.sha256" ]; then
        (cd "$(dirname "$archive")" && sha256sum -c "$(basename "$archive").sha256") \
            || die "checksum MISMATCH - this archive is corrupt"
        say "checksum ok"
    else
        warn "no .sha256 alongside; skipping integrity check"
    fi
    case "$archive" in
        *.gpg)
            [ -f "$PASSPHRASE_FILE" ] || die "encrypted archive but no passphrase file"
            gpg --batch --quiet --yes --passphrase-file "$PASSPHRASE_FILE" \
                --decrypt "$archive" 2>/dev/null | zstd -dc | tar -tf - >/dev/null \
                || die "archive will not decrypt/extract"
            ;;
        *) zstd -dc "$archive" | tar -tf - >/dev/null || die "archive will not extract" ;;
    esac
    say "archive is readable and complete: $archive"
    exit 0
fi

AUTO=false; INCLUDE_LOGS=true
for arg in "$@"; do
    case "$arg" in
        --auto) AUTO=true ;;
        --no-logs) INCLUDE_LOGS=false ;;
        *) die "unknown option: $arg" ;;
    esac
done

[ -d "$SRC" ] || die "source directory missing: $SRC"
command -v zstd >/dev/null || die "zstd is not installed"

# --auto sorts into daily/weekly/monthly the same way /rmm/backup.sh does.
if [ "$AUTO" = true ]; then
    month_day=$(date +'%d'); week_day=$(date +'%u')
    if [ "$month_day" -eq 10 ]; then bucket="monthly"
    elif [ "$week_day" -eq 5 ]; then bucket="weekly"
    else bucket="daily"; fi
    OUT_DIR="${DEST}/${bucket}"
else
    OUT_DIR="${DEST}"
fi

mkdir -p "$OUT_DIR" || die "cannot create $OUT_DIR (run as root, or create /rmmbackups first)"
chmod 700 "$DEST" 2>/dev/null || true

tmp_dir="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$tmp_dir'" EXIT

stage="${tmp_dir}/mcp"
mkdir -p "$stage"

# --- what goes in -----------------------------------------------------------
copy() { [ -e "${SRC}/$1" ] && cp -a "${SRC}/$1" "${stage}/" || true; }

copy .env
copy trmm_mcp
copy certs
copy state
copy requirements.txt
copy trmm-mcp.service
copy run.sh
copy README.md
copy docs
copy command-audit.log
for f in "${SRC}"/*.py; do [ -e "$f" ] && cp -a "$f" "${stage}/" || true; done

if [ "$INCLUDE_LOGS" = true ] && [ -d "${SRC}/logs" ]; then
    cp -a "${SRC}/logs" "${stage}/"
fi

# A restore is only as good as knowing what you restored.
{
    echo "TacticalRMM MCP server backup"
    echo "created:  $(date -Is)"
    echo "host:     $(hostname)"
    echo "source:   ${SRC}"
    echo "logs:     ${INCLUDE_LOGS}"
    echo
    echo "Restore:"
    echo "  1. tar -xf <archive> -C /tmp        (decrypt/decompress first, see README)"
    echo "  2. cp -a /tmp/mcp/. ${SRC}/"
    echo "  3. cd ${SRC} && python3.11 -m venv venv"
    echo "     ./venv/bin/pip install -r requirements.txt"
    echo "  4. sudo cp trmm-mcp.service /etc/systemd/system/"
    echo "     sudo systemctl daemon-reload && sudo systemctl restart trmm-mcp"
    echo
    echo "NOTE: .env holds the TRMM API keys, the bearer token and the approval"
    echo "password hash + TOTP secret. Treat this archive as a credential store."
    echo
    echo "Contents:"
} > "${stage}/RESTORE.txt"
(cd "$stage" && find . -type f -printf '%10s  %p\n' | sort -k2) >> "${stage}/RESTORE.txt"

# Per-file hashes, so a partial corruption is identifiable after restore.
(cd "$stage" && find . -type f ! -name MANIFEST.sha256 -exec sha256sum {} + \
    > MANIFEST.sha256)

# --- pack -------------------------------------------------------------------
base="mcp-backup-${STAMP}.tar.zst"
archive="${OUT_DIR}/${base}"

tar -cf - -C "$tmp_dir" mcp | zstd -19 -q -o "${tmp_dir}/${base}"

if [ -f "$PASSPHRASE_FILE" ]; then
    gpg --batch --quiet --yes --symmetric --cipher-algo AES256 \
        --passphrase-file "$PASSPHRASE_FILE" \
        --output "${tmp_dir}/${base}.gpg" "${tmp_dir}/${base}"
    archive="${archive}.gpg"
    mv "${tmp_dir}/${base}.gpg" "$archive"
    encrypted="yes"
else
    mv "${tmp_dir}/${base}" "$archive"
    encrypted="no"
fi

chmod 600 "$archive"
(cd "$OUT_DIR" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
chmod 600 "${archive}.sha256"

# --- verify before pruning: never delete old backups on the strength of a new
#     one we have not proved is readable ---------------------------------------
"$0" --verify "$archive" >/dev/null || die "new archive failed verification; nothing pruned"

size=$(du -h "$archive" | cut -f1)
say "backup ok: ${archive} (${size}, encrypted=${encrypted})"

if [ "$AUTO" = true ]; then
    find "${DEST}/daily"   -type f -mtime +14  -name 'mcp-backup-*' -delete 2>/dev/null || true
    find "${DEST}/weekly"  -type f -mtime +60  -name 'mcp-backup-*' -delete 2>/dev/null || true
    find "${DEST}/monthly" -type f -mtime +380 -name 'mcp-backup-*' -delete 2>/dev/null || true
    say "rotation applied (daily 14d / weekly 60d / monthly 380d)"
fi
