"use client";

import { useEffect, useRef } from "react";

export function SelectionCheckbox({
  checked,
  mixed,
  onChange,
  children,
}: {
  checked: boolean;
  mixed: boolean;
  onChange: (checked: boolean) => void;
  children: React.ReactNode;
}) {
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (input.current) input.current.indeterminate = mixed;
  }, [mixed]);
  return (
    <label className="mb-2 flex items-center gap-2 text-xs text-muted">
      <input
        ref={input}
        type="checkbox"
        checked={checked}
        aria-checked={mixed ? "mixed" : checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      {children}
    </label>
  );
}
