#!/usr/bin/env bash
set -euo pipefail

DEST="${1:-}"
PROFILE="${2:-server}"   # minimal|workstation|server|web|dc|custom
MODE="${3:-copy}"        # copy|mirror
DO_HASH="${4:-hash}"     # hash|nohash

if [[ -z "$DEST" ]]; then
  echo "Usage: $0 <DEST> [profile] [copy|mirror] [hash|nohash]"
  exit 1
fi

RUNID="$(hostname)_$(date -u +%Y%m%d_%H%M%S)Z"
OUT="${DEST%/}/clone_${RUNID}"
LOGDIR="${OUT}/logs"
mkdir -p "$LOGDIR"

META="${LOGDIR}/metadata.txt"
RSYNCLOG="${LOGDIR}/rsync.log"
MANIFEST="${OUT}/manifest.csv"

declare -a PATHS=()
case "$PROFILE" in
  minimal)
    PATHS=(/etc /var/log /home /root)
    ;;
  workstation)
    PATHS=(/etc /var/log /home /root /usr/local/bin /opt)
    ;;
  server)
    PATHS=(/etc /var/log /home /root /usr/local/bin /opt /srv /var/www)
    ;;
  web)
    PATHS=(/etc /var/log /var/www /srv /home /root /usr/local/bin /opt)
    ;;
  dc)
    # "dc" here means "auth-ish" Linux roles; tune for your stack (sssd/krb/ldap)
    PATHS=(/etc /var/log /home /root /usr/local/bin /opt /var/lib/sss /var/lib/krb5)
    ;;
  custom)
    shift 4
    PATHS=("$@")
    if [[ ${#PATHS[@]} -eq 0 ]]; then
      echo "Custom profile requires paths after the first 4 args."
      exit 1
    fi
    ;;
  *)
    echo "Unknown profile: $PROFILE"
    exit 1
    ;;
esac

# Filter existing
EXISTING=()
for p in "${PATHS[@]}"; do
  [[ -e "$p" ]] && EXISTING+=("$p")
done

cat > "$META" <<EOF
RunId:        $RUNID
Host:         $(hostname)
User:         $(id -un)
StartedUTC:   $(date -u +%Y-%m-%dT%H:%M:%SZ)
Profile:      $PROFILE
Mode:         $MODE
Destination:  $DEST
Paths:
$(printf "%s\n" "${EXISTING[@]}")
EOF

# rsync options:
# -aHAX tries to preserve perms, hardlinks, ACLs, xattrs (best effort)
# --numeric-ids helps keep UID/GID consistent in restores
# Excludes skip pseudo-fs + huge/noisy areas
RSYNC_OPTS=(-aHAX --numeric-ids --info=stats2 --log-file="$RSYNCLOG" \
  --exclude=/proc --exclude=/sys --exclude=/dev --exclude=/run --exclude=/tmp \
  --exclude=/var/lib/docker --exclude=/var/lib/containerd --exclude=/var/cache)

if [[ "$MODE" == "mirror" ]]; then
  RSYNC_OPTS+=(--delete)
fi

mkdir -p "$OUT/data"

for src in "${EXISTING[@]}"; do
  name="$(echo "$src" | sed 's#^/##; s#/#_#g')"
  mkdir -p "$OUT/data/$name"
  rsync "${RSYNC_OPTS[@]}" "$src/" "$OUT/data/$name/"
done

echo "RelativePath,SizeBytes,LastWriteTimeUtc,SHA256" > "$MANIFEST"
cd "$OUT" >/dev/null

# Manifest
while IFS= read -r -d '' f; do
  rel="${f#./}"
  size="$(stat -c '%s' "$f" 2>/dev/null || echo 0)"
  mtime="$(date -u -d "@$(stat -c '%Y' "$f")" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")"
  sha=""
  if [[ "$DO_HASH" == "hash" ]]; then
    sha="$(sha256sum "$f" | awk '{print $1}' || echo HASH_ERROR)"
  fi
  printf '"%s",%s,"%s","%s"\n' "$rel" "$size" "$mtime" "$sha" >> "$MANIFEST"
done < <(find . -type f -print0)

cd - >/dev/null
echo "Done. Output: $OUT"
echo "Logs: $LOGDIR"
echo "Manifest: $MANIFEST"
