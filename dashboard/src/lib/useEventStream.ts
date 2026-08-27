import { useCallback, useEffect, useRef, useState } from "react";
import { streamUrl, type DashboardApi, type EventRecord } from "../api";

export type StreamState = "connecting" | "live" | "retrying" | "offline";

type Options = {
  api?: DashboardApi;
  enabled: boolean;
  onEvent: (event: EventRecord) => void;
};

/**
 * Keeps a WebSocket open to the control plane so decisions surface the moment they are journalled. The socket is
 * authorised with a short-lived ticket because a browser cannot attach basic credentials to a handshake; a lost
 * connection reconnects with a capped backoff, and the caller falls back to polling while the stream is down.
 */
export function useEventStream({ api, enabled, onEvent }: Options) {
  const [state, setState] = useState<StreamState>("offline");
  const [received, setReceived] = useState(0);
  const [lastEventAt, setLastEventAt] = useState<Date>();
  const socketRef = useRef<WebSocket | undefined>(undefined);
  const attemptRef = useRef(0);
  const timerRef = useRef<number | undefined>(undefined);
  const closedRef = useRef(false);
  const handlerRef = useRef(onEvent);
  handlerRef.current = onEvent;

  const connect = useCallback(async () => {
    if (!api || closedRef.current) return;
    setState((current) => (current === "live" ? "retrying" : current === "offline" ? "connecting" : current));
    try {
      const { ticket } = await api.streamTicket();
      if (closedRef.current) return;
      const socket = new WebSocket(streamUrl(ticket));
      socketRef.current = socket;

      socket.onopen = () => {
        attemptRef.current = 0;
        setState("live");
      };
      socket.onmessage = (message) => {
        try {
          const frame = JSON.parse(message.data as string);
          if (frame.type === "event" && frame.event) {
            setReceived((count) => count + 1);
            setLastEventAt(new Date());
            handlerRef.current(frame.event as EventRecord);
          }
        } catch {
          /* A malformed frame must never break the live view. */
        }
      };
      socket.onclose = () => {
        socketRef.current = undefined;
        if (closedRef.current) return;
        setState("retrying");
        scheduleReconnect();
      };
      socket.onerror = () => socket.close();
    } catch {
      if (!closedRef.current) {
        setState("retrying");
        scheduleReconnect();
      }
    }

    function scheduleReconnect() {
      attemptRef.current = Math.min(attemptRef.current + 1, 6);
      const delay = Math.min(15_000, 800 * 2 ** (attemptRef.current - 1));
      window.clearTimeout(timerRef.current);
      timerRef.current = window.setTimeout(() => void connect(), delay);
    }
  }, [api]);

  useEffect(() => {
    if (!enabled || !api) {
      closedRef.current = true;
      window.clearTimeout(timerRef.current);
      socketRef.current?.close();
      socketRef.current = undefined;
      setState("offline");
      return;
    }
    closedRef.current = false;
    void connect();
    return () => {
      closedRef.current = true;
      window.clearTimeout(timerRef.current);
      socketRef.current?.close();
      socketRef.current = undefined;
    };
  }, [api, enabled, connect]);

  return { state, received, lastEventAt };
}
