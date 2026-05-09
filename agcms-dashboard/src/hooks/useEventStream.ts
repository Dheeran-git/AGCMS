import { useEffect, useRef, useState } from 'react';
import { useAuthStore } from '../stores/auth';

export type StreamStatus = 'connecting' | 'open' | 'reconnecting' | 'closed';

interface UseEventStreamOptions<T> {
  /** Server-Sent Events URL — relative paths are fine (Vite dev proxy). */
  url: string;
  /** Map of event name → handler. ``message`` catches the default event. */
  handlers: Record<string, (data: T) => void>;
  /** Whether the stream should be active. Defaults to true. */
  enabled?: boolean;
  /** Reconnect delay in ms after a transient drop. */
  reconnectMs?: number;
}

/**
 * Subscribes to a Server-Sent Events stream with bearer-token auth.
 *
 * The native ``EventSource`` API can't send custom headers, so we use
 * ``fetch`` + a streaming reader instead. This also gives us a clean
 * ``AbortController`` cancellation path on unmount.
 */
export function useEventStream<T = unknown>({
  url,
  handlers,
  enabled = true,
  reconnectMs = 3000,
}: UseEventStreamOptions<T>): { status: StreamStatus; error: Error | null } {
  const [status, setStatus] = useState<StreamStatus>('connecting');
  const [error, setError] = useState<Error | null>(null);
  // Pin the latest handlers so we don't tear the connection down on each render.
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  useEffect(() => {
    if (!enabled) {
      setStatus('closed');
      return;
    }

    const abort = new AbortController();
    let cancelled = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    const connect = async () => {
      setStatus((s) => (s === 'closed' ? 'connecting' : s));
      const token = useAuthStore.getState().token;
      try {
        const resp = await fetch(url, {
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'text/event-stream',
          },
          signal: abort.signal,
        });
        if (!resp.ok || !resp.body) {
          throw new Error(`SSE ${resp.status}: ${await resp.text()}`);
        }
        setStatus('open');
        setError(null);

        const reader = resp.body.pipeThrough(new TextDecoderStream()).getReader();
        let buffer = '';
        while (!cancelled) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += value;
          // SSE frames are separated by a blank line. Process whatever's complete.
          let sep: number;
          while ((sep = buffer.indexOf('\n\n')) !== -1) {
            const frame = buffer.slice(0, sep);
            buffer = buffer.slice(sep + 2);
            dispatchFrame(frame, handlersRef.current);
          }
        }
      } catch (err) {
        if (cancelled) return;
        setError(err as Error);
        setStatus('reconnecting');
        reconnectTimer = setTimeout(connect, reconnectMs);
      }
    };

    void connect();

    return () => {
      cancelled = true;
      abort.abort();
      if (reconnectTimer) clearTimeout(reconnectTimer);
      setStatus('closed');
    };
  }, [url, enabled, reconnectMs]);

  return { status, error };
}

function dispatchFrame<T>(frame: string, handlers: Record<string, (data: T) => void>) {
  let event = 'message';
  const dataLines: string[] = [];
  for (const line of frame.split('\n')) {
    if (line.startsWith(':')) continue; // comment / heartbeat
    if (line.startsWith('event:')) {
      event = line.slice(6).trim();
    } else if (line.startsWith('data:')) {
      dataLines.push(line.slice(5).trimStart());
    }
  }
  if (dataLines.length === 0) return;
  const payload = dataLines.join('\n');
  const handler = handlers[event];
  if (!handler) return;
  try {
    handler(JSON.parse(payload) as T);
  } catch {
    // Non-JSON payload — pass the raw string through.
    handler(payload as unknown as T);
  }
}
