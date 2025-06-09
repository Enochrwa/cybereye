// frontend/src/hooks/createSocketHook.ts
import { useEffect, useRef, useState, useCallback } from 'react';
import { io, Socket } from 'socket.io-client';
import { throttle } from 'lodash';
import { SocketEvent } from './useSocket'; // reuse your event types

interface UseSocketReturn {
  socket: Socket | null;
  isConnected: boolean;
  connectionError: string | null;
  connect: () => void;
  disconnect: () => void;
  emitEvent: <T extends SocketEvent['type']>(
    type: T,
    data: Extract<SocketEvent, { type: T }>['data']
  ) => void;
  subscribe: <T extends SocketEvent['type']>(
    eventType: T,
    handler: (data: Extract<SocketEvent, { type: T }>['data']) => void
  ) => void;
  unsubscribe: <T extends SocketEvent['type']>(
    eventType: T,
    handler: (data: Extract<SocketEvent, { type: T }>['data']) => void
  ) => void;
}

export function createSocketHook(namespace: string): () => UseSocketReturn {
  return function useNamespaceSocket() {
    const socketRef = useRef<Socket | null>(null);
    const [isConnected, setIsConnected] = useState(false);
    const [connectionError, setConnectionError] = useState<string | null>(null);
    const initialized = useRef(false);
    const handlers = useRef(new Map<SocketEvent['type'], Set<Function>>());

    const handleEvent = useCallback((event: SocketEvent) => {
      const registered = handlers.current.get(event.type);
      registered?.forEach(handler => handler(event.data));
    }, []);

    const connect = useCallback(() => {
      if (socketRef.current?.connected || initialized.current) return;

      const newSocket = io(`http://127.0.0.1:8000/${namespace}`, {
        path: '/socket.io',
        transports: ['websocket'],
        reconnectionAttempts: 5,
        reconnectionDelay: 3000,
        autoConnect: false,
        upgrade: false,
      });

      newSocket
        .on('connect', () => {
          setIsConnected(true);
          setConnectionError(null);
          console.log(`✅ Connected to namespace: /${namespace}`);
        })
        .on('connect_error', (err) => {
          setConnectionError(err.message);
          console.error(`❌ Connection Error (/ ${namespace}):`, err);
        })
        .on('disconnect', () => {
          setIsConnected(false);
          console.warn(`⚠️ Disconnected from namespace: /${namespace}`);
        });

      newSocket.onAny((event, data) => {
        handleEvent({ type: event, data } as SocketEvent);
      });

      newSocket.connect();
      socketRef.current = newSocket;
      initialized.current = true;
    }, [handleEvent]);

    const disconnect = useCallback(() => {
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
        initialized.current = false;
        setIsConnected(false);
        console.log(`🔌 Disconnected from namespace: /${namespace}`);
      }
    }, []);

    const emitEvent = useCallback<UseSocketReturn['emitEvent']>((type, data) => {
      if (socketRef.current?.connected) {
        socketRef.current.emit(type, data);
      } else {
        console.warn(`⚠️ Cannot emit event (${type}) - socket not connected (/ ${namespace})`);
      }
    }, []);

    const subscribe = useCallback<UseSocketReturn['subscribe']>((eventType, handler) => {
      if (!handlers.current.has(eventType)) {
        handlers.current.set(eventType, new Set());
      }
      handlers.current.get(eventType)?.add(handler);
    }, []);

    const unsubscribe = useCallback<UseSocketReturn['unsubscribe']>((eventType, handler) => {
      handlers.current.get(eventType)?.delete(handler);
    }, []);

    useEffect(() => {
      connect();
      return () => {
        disconnect();
        handlers.current.clear();
      };
    }, [connect, disconnect]);

    return {
      socket: socketRef.current,
      isConnected,
      connectionError,
      connect,
      disconnect,
      emitEvent,
      subscribe,
      unsubscribe,
    };
  };
}
