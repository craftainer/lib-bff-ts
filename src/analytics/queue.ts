import type { Log } from "./types.ts";

/** Options of {@link BoundedQueue}. */
export interface QueueOptions<T> {
  capacity: number;
  intervalMs: number;
  deliver: (items: T[]) => Promise<void>;
  log: Log;
}

/**
 * A bounded, fire-and-forget buffer. `push` never blocks or throws: an item
 * that arrives while the buffer is full is dropped, and the number dropped
 * is logged once per flush window. A timer (unref'd, started by the first
 * push) flushes every `intervalMs`; `close()` stops it and flushes the rest.
 * A failing `deliver` is logged and its batch discarded.
 */
export class BoundedQueue<T> {
  readonly #items: T[] = [];
  readonly #options: QueueOptions<T>;
  #dropped = 0;
  #closed = false;
  #timer: NodeJS.Timeout | undefined;
  #chain: Promise<void> = Promise.resolve();

  constructor(options: QueueOptions<T>) {
    this.#options = options;
  }

  push(item: T): void {
    if (this.#closed) {
      return;
    }
    if (this.#items.length >= this.#options.capacity) {
      this.#dropped += 1;
      return;
    }
    this.#items.push(item);
    this.#timer ??= setInterval(() => {
      void this.flush();
    }, this.#options.intervalMs).unref();
  }

  /** Delivers everything queued now. Flushes never overlap. */
  flush(): Promise<void> {
    this.#chain = this.#chain.then(() => this.#drain());
    return this.#chain;
  }

  /** Stops the timer, flushes what is left and ignores later pushes. */
  async close(): Promise<void> {
    this.#closed = true;
    clearInterval(this.#timer);
    await this.flush();
  }

  async #drain(): Promise<void> {
    if (this.#dropped > 0) {
      this.#options.log.warn(
        { dropped: this.#dropped },
        "analytics queue full: events dropped",
      );
      this.#dropped = 0;
    }
    const batch = this.#items.splice(0);
    if (batch.length === 0) {
      return;
    }
    try {
      await this.#options.deliver(batch);
    } catch (error) {
      this.#options.log.warn(
        { err: String(error), events: batch.length },
        "analytics delivery failed",
      );
    }
  }
}
