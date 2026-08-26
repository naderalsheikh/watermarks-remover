// Extracted from web/app/matters/view/page.tsx and .../job/page.tsx (the
// 2026-08-25 permission-awareness pass): both pages independently wrote
// `perms.has("inspect") ? undefined : "You don't have inspect permission
// on this matter"`-shaped conditionals at every gated control, which is
// exactly the kind of duplicated string/logic that drifts silently --
// one page's wording changes, another's doesn't, and nothing catches it.

export type MatterPerm =
  | "read"
  | "upload"
  | "inspect"
  | "sanitize"
  | "download_original"
  | "admin";

// perms is undefined while the owning matter fetch hasn't resolved yet --
// treated as "no permissions", the safe default (a gated control must
// never render as usable before we've actually confirmed the grant).
export function hasMatterPerm(perms: string[] | undefined, perm: MatterPerm): boolean {
  return (perms ?? []).includes(perm);
}

export type PermissionGate = { allowed: boolean; title: string | undefined };

// For an action control that should stay visible but disabled when the
// permission is missing (Upload, per-document Inspect/Sanitize) -- title
// is meant to be spread onto the button's `title` attribute, undefined
// (no tooltip) when the action is actually allowed.
export function permissionGate(perms: string[] | undefined, perm: MatterPerm): PermissionGate {
  const allowed = hasMatterPerm(perms, perm);
  return {
    allowed,
    title: allowed ? undefined : `You don't have ${perm} permission on this matter`,
  };
}
