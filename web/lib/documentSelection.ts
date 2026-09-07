/** Select only the rows the operator can see, preserving explicit selections
 * outside the current filter. The UI must disclose those hidden selections. */
export function toggleVisibleSelection(
  selected: ReadonlySet<string>,
  visibleIds: readonly string[],
  checked: boolean,
): Set<string> {
  const next = new Set(selected);
  for (const id of visibleIds) {
    if (checked) next.add(id);
    else next.delete(id);
  }
  return next;
}

export function selectionSummary(selected: ReadonlySet<string>, visibleIds: readonly string[]) {
  const visible = new Set(visibleIds);
  const visibleSelected = [...selected].filter((id) => visible.has(id)).length;
  return {
    visibleSelected,
    hiddenSelected: selected.size - visibleSelected,
    allVisibleSelected: visible.size > 0 && visibleSelected === visible.size,
    someVisibleSelected: visibleSelected > 0 && visibleSelected < visible.size,
  };
}
