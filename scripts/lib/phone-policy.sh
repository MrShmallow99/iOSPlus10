# Sourced by phone mutation entry points. No environment override is supported.
phone_require_destructive_policy() {
  policy_root=$(CDPATH= cd "$(dirname "$0")/../.." && pwd) || return 78
  policy=$(cat "$policy_root/config/phone-storage-policy" 2>/dev/null) || policy=missing
  if [ "$policy" != destructive-ios ]; then
    echo "Blocked: this checkout preserves Android boot and app data." >&2
    echo "Existing flash/restore/RAM-test workflows are not approved preservation paths." >&2
    echo "Policy: $policy_root/config/phone-storage-policy ($policy). See docs/android-preservation.md." >&2
    return 78
  fi
}
