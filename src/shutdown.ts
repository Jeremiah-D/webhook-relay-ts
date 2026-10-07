import type { Server } from "node:http";

export type ShutdownSignal = "SIGTERM" | "SIGINT";

export type ShutdownEvent =
  | { type: "signal"; signal: ShutdownSignal }
  | { type: "server-closed" }
  | { type: "drained" }
  | { type: "drain-timeout" };

export interface GracefulShutdownOptions {
  /** Signals that trigger shutdown. Default: ["SIGTERM", "SIGINT"]. */
  signals?: ShutdownSignal[];
  /** Process exit hook; injectable so tests can observe instead of exiting. */
  exit?: (code: number) => void;
  /** Observability hook for the shutdown sequence. */
  onEvent?: (event: ShutdownEvent) => void;
}

/**
 * Install one-shot signal handling for graceful shutdown.
 *
 * On the first signal: the HTTP server stops accepting new connections (idle
 * keep-alive connections are dropped so `close()` is not held open by them),
 * then `drain()` runs — typically `() => queue.shutdown(timeoutMs)` — to let
 * in-flight deliveries settle. The process exits 0 when everything drained,
 * 1 when the drain timed out (a hung downstream must not pin the process
 * forever).
 *
 * Note: a connection that is busy when the signal arrives and goes idle
 * afterwards waits out the server's `keepAliveTimeout` (default 5s) before
 * `close()` resolves — the standard Node shutdown semantic.
 *
 * Returns an uninstall function that removes the signal listeners.
 */
export function installGracefulShutdown(
  server: Server,
  drain: () => Promise<boolean>,
  opts: GracefulShutdownOptions = {}
): () => void {
  const signals = opts.signals ?? ["SIGTERM", "SIGINT"];
  const exit = opts.exit ?? ((code: number) => process.exit(code));
  let shuttingDown = false;

  const listeners: Array<[ShutdownSignal, () => void]> = [];
  for (const sig of signals) {
    const handler = (): void => {
      if (shuttingDown) return;
      shuttingDown = true;
      opts.onEvent?.({ type: "signal", signal: sig });
      void (async () => {
        // 1. Stop accepting new connections. Idle keep-alives are dropped;
        //    in-flight requests still run to completion before `close()`
        //    resolves.
        await new Promise<void>((resolve) => {
          server.close(() => resolve());
          server.closeIdleConnections();
        });
        opts.onEvent?.({ type: "server-closed" });
        // 2. Wait for in-flight deliveries to settle.
        const drained = await drain();
        opts.onEvent?.({ type: drained ? "drained" : "drain-timeout" });
        exit(drained ? 0 : 1);
      })();
    };
    listeners.push([sig, handler]);
    process.once(sig, handler);
  }

  return () => {
    for (const [sig, handler] of listeners) {
      process.removeListener(sig, handler);
    }
  };
}
