type Callbacks<P> = {
  onPage: (page: P) => void;
  onError: (error: unknown) => void;
  onStart?: () => void;
  onSettled?: () => void;
};

/** One query/reload lifetime. Cancellation silences every completion callback;
 * the offset guard also rejects duplicate clicks made before React rerenders. */
export function createPaginationScope<P extends { items: unknown[] }>(
  requestKey: string,
) {
  let active = true;
  let pending = false;
  let nextOffset = 0;

  return {
    requestKey,
    cancel() {
      active = false;
    },
    async run(
      offset: number,
      fetchPage: (offset: number) => Promise<P>,
      callbacks: Callbacks<P>,
    ) {
      if (!active || pending || offset !== nextOffset) return;
      pending = true;
      try {
        callbacks.onStart?.();
        const page = await fetchPage(offset);
        if (!active) return;
        nextOffset += page.items.length;
        callbacks.onPage(page);
      } catch (error: unknown) {
        if (active) callbacks.onError(error);
      } finally {
        pending = false;
        if (active) callbacks.onSettled?.();
      }
    },
  };
}
