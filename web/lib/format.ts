// A legal-custody record read by reviewers in different timezones must not
// rely on the reader's browser clock to disambiguate "when" — bare
// toLocaleString() output carries no zone at all. Every timestamp always
// shows both the reader's local time (with its zone abbreviation) and the
// unambiguous UTC instant.
export function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const local = d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
  const zone =
    new Intl.DateTimeFormat(undefined, { timeZoneName: "short" })
      .formatToParts(d)
      .find((p) => p.type === "timeZoneName")?.value ?? "";
  const utc = d.toISOString().slice(0, 19).replace("T", " ");
  return `${local}${zone ? ` ${zone}` : ""} (${utc} UTC)`;
}
