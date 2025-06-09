// Fixed socket hook with improved connection management
import { useEffect, useCallback, useState, useRef } from 'react';
import { io, Socket } from 'socket.io-client';
import { useDispatch } from 'react-redux';
import config, { isDebugEnabled } from '@/config';
import { setIsBackendUp } from '@/app/slices/displaySlice';

// Import all the action creators and types
import {
  addHttpActivity,
  addTcpActivity,
  addUdpActivity,
  addIcmpActivity,
  addArpActivity,
  addPayloadAnalysisEvent,
  addBehaviorAnalysisEvent,
} from '@/app/slices/socketSlice';

import {
  addDnsActivity,
  addFirewallEvent,
  addThreatDetection,
  addIPv6Activity,
  addPacketEntry,
  updateSystemStats,
  updateSystemStatus,
  addSecurityAlert,
  addPhishingDetection,
  addThreatResponse,
  addQuarantinedFile,
  addNetworkVolume,
} from '@/app/slices/realtimeDataSlice';

// Types (simplified and cleaned up)
export interface Alert {
  id: string;
  timestamp: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  source_ip?: string;
  destination_ip?: string;
  destination_port?: number;
  protocol?: string;
  description: string;
  threat_type: string;
  rule_id?: string;
  metadata?: Record<string, any>;
}

export interface HttpActivity {
  id: string;
  timestamp: string;
  source_ip?: string;
  source_port?: number;
  destination_ip?: string;
  destination_port?: number;
  method?: string;
  host?: string;
  path?: string;
  status_code?: number;
  user_agent?: string;
  content_type?: string;
  protocol?: string;
  payload_size?: number;
  threat_score?: number;
  risk_level?: "Critical" | "High" | "Medium" | "Low" | "Info";
}

export interface SystemStats {
  id?: string;
  timestamp: string;
  cpu_usage_percent?: number;
  memory_usage_percent?: number;
  network_packets_per_minute?: number;
  cpu?: number;
  memory?: number;
  network?: number;
  top_talkers?: Array<{ ip: string; packets: number; }>;
  threat_distribution?: Array<{ threat_type: string; count: number; }>;
  queue_stats?: Record<string, any>;
}

export interface NetworkTrafficVolume {
  networkVolume: number;
}

// Connection state
interface ConnectionState {
  isConnected: boolean;
  connectionError: string | null;
  retryAttempts: number;
  lastConnectedAt: Date | null;
}

// Hook return type
export interface UseSocketReturn {
  socket: Socket | null;
  isConnected: boolean;
  connectionError: string | null;
  retryAttempts: number;
  connect: () => void;
  disconnect: () => void;
  emitEvent: (eventType: string, data: any) => void;
}

// Connection manager class
class SocketConnectionManager {
  private socket: Socket | null = null;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private maxRetries = 5;
  private retryDelay = 5000; // 5 seconds
  private retryAttempts = 0;
  private isManuallyDisconnected = false;
  private eventHandlers = new Map<string, Function>();

  constructor(
    private url: string,
    private namespace: string,
    private onStateChange: (state: Partial<ConnectionState>) => void
  ) {}

  connect(): void {
    if (this.socket?.connected) {
      if (isDebugEnabled) console.log('Socket already connected');
      return;
    }

    this.isManuallyDisconnected = false;
    this.createSocket();
  }

  disconnect(): void {
    this.isManuallyDisconnected = true;
    this.clearReconnectTimer();
    
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
    
    this.onStateChange({
      isConnected: false,
      connectionError: 'Disconnected by user',
      retryAttempts: 0
    });
  }

  private createSocket(): void {
    try {
      this.socket = io(`${this.url}${this.namespace}`, {
        path: '/socket.io',
        transports: ['websocket', 'polling'],
        reconnection: false, // We handle reconnection manually
        timeout: 10000,
        forceNew: true,
      });

      this.setupEventListeners();
      
      if (isDebugEnabled) {
        console.log(`🔌 Attempting to connect to: ${this.url}${this.namespace}`);
      }
    } catch (error) {
      console.error('Failed to create socket:', error);
      this.handleConnectionError(error as Error);
    }
  }

  private setupEventListeners(): void {
    if (!this.socket) return;

    this.socket.on('connect', () => {
      if (isDebugEnabled) console.log('✅ Socket connected');
      
      this.retryAttempts = 0;
      this.clearReconnectTimer();
      
      this.onStateChange({
        isConnected: true,
        connectionError: null,
        retryAttempts: 0,
        lastConnectedAt: new Date()
      });
    });

    this.socket.on('disconnect', (reason) => {
      if (isDebugEnabled) console.log(`⚠️ Socket disconnected: ${reason}`);
      
      this.onStateChange({
        isConnected: false,
        connectionError: `Disconnected: ${reason}`
      });

      if (!this.isManuallyDisconnected && reason !== 'io client disconnect') {
        this.scheduleReconnect();
      }
    });

    this.socket.on('connect_error', (error) => {
      console.error('❌ Socket connection error:', error);
      this.handleConnectionError(error);
    });

    // Register event handlers
    this.eventHandlers.forEach((handler, eventType) => {
      this.socket?.on(eventType, handler);
    });
  }

  private handleConnectionError(error: Error): void {
    this.onStateChange({
      isConnected: false,
      connectionError: error.message
    });

    if (!this.isManuallyDisconnected) {
      this.scheduleReconnect();
    }
  }

  private scheduleReconnect(): void {
    if (this.retryAttempts >= this.maxRetries) {
      this.onStateChange({
        connectionError: `Failed to connect after ${this.maxRetries} attempts`
      });
      return;
    }

    this.retryAttempts++;
    this.onStateChange({ retryAttempts: this.retryAttempts });

    const delay = this.retryDelay * Math.pow(1.5, this.retryAttempts - 1); // Exponential backoff
    
    if (isDebugEnabled) {
      console.log(`🔄 Scheduling reconnect attempt ${this.retryAttempts}/${this.maxRetries} in ${delay}ms`);
    }

    this.reconnectTimer = setTimeout(() => {
      this.createSocket();
    }, delay);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  registerEventHandler(eventType: string, handler: Function): void {
    this.eventHandlers.set(eventType, handler);
    this.socket?.on(eventType, handler);
  }

  unregisterEventHandler(eventType: string): void {
    const handler = this.eventHandlers.get(eventType);
    if (handler) {
      this.socket?.off(eventType, handler);
      this.eventHandlers.delete(eventType);
    }
  }

  emit(eventType: string, data: any): void {
    if (this.socket?.connected) {
      this.socket.emit(eventType, data);
    } else {
      console.warn(`Cannot emit ${eventType}: socket not connected`);
    }
  }

  cleanup(): void {
    this.clearReconnectTimer();
    this.eventHandlers.clear();
    
    if (this.socket) {
      this.socket.disconnect();
      this.socket = null;
    }
  }
}

// Main hook
export default function usePacketSniffer(): UseSocketReturn {
  const dispatch = useDispatch();
  const [connectionState, setConnectionState] = useState<ConnectionState>({
    isConnected: false,
    connectionError: null,
    retryAttempts: 0,
    lastConnectedAt: null
  });

  const connectionManagerRef = useRef<SocketConnectionManager | null>(null);

  // Event handlers configuration
  const eventHandlers = useRef({
    // Security events
    'threat_detected': (data: Alert) => {
      dispatch(addThreatDetection(data));
      dispatch(addSecurityAlert(data));
    },
    'critical_alert': (data: Alert) => {
      dispatch(addSecurityAlert(data));
    },
    'security_alert': (data: Alert) => {
      dispatch(addSecurityAlert(data));
    },
    'user_alert': (data: Alert) => {
      dispatch(addSecurityAlert(data));
    },
    'phishing_link_detected': (data: any) => {
      dispatch(addPhishingDetection(data));
    },

    // System events
    'system_stats': (data: SystemStats) => {
      dispatch(updateSystemStats(data));
    },
    'system_status': (data: any) => {
      dispatch(updateSystemStatus(data));
    },

    // Network events
    'packet_bytes': (data: NetworkTrafficVolume) => {
      dispatch(addNetworkVolume(data));
    },
    'firewall_event': (data: any) => {
      dispatch(addFirewallEvent(data));
    },
    'packet_data': (data: any) => {
      dispatch(addPacketEntry(data));
    },
    'dns_activity': (data: any) => {
      dispatch(addDnsActivity(data));
    },
    'ipv6_activity': (data: any) => {
      dispatch(addIPv6Activity(data));
    },

    // Protocol activities
    'http_activity': (data: HttpActivity[]) => {
      dispatch(addHttpActivity(data));
    },
    'tcp_activity': (data: any[]) => {
      dispatch(addTcpActivity(data));
    },
    'udp_activity': (data: any[]) => {
      dispatch(addUdpActivity(data));
    },
    'icmp_activity': (data: any[]) => {
      dispatch(addIcmpActivity(data));
    },
    'arp_activity': (data: any[]) => {
      dispatch(addArpActivity(data));
    },
    'payload_analysis': (data: any[]) => {
      dispatch(addPayloadAnalysisEvent(data));
    },
    'behavior_analysis': (data: any[]) => {
      dispatch(addBehaviorAnalysisEvent(data));
    },

    // Response events
    'threat_response': (data: any) => {
      dispatch(addThreatResponse(data));
    },
    'file_quarantined': (data: any) => {
      dispatch(addQuarantinedFile(data));
    },

    // Connection status
    'server_ready': () => {
      dispatch(setIsBackendUp(true));
    },
    'startup_progress': (data: any) => {
      if (isDebugEnabled) console.log('Server startup progress:', data);
    }
  });

  // State change handler
  const handleStateChange = useCallback((newState: Partial<ConnectionState>) => {
    setConnectionState(prev => ({ ...prev, ...newState }));
    
    // Update backend status
    if (newState.isConnected !== undefined) {
      dispatch(setIsBackendUp(newState.isConnected));
    }
  }, [dispatch]);

  // Initialize connection manager
  useEffect(() => {
    const manager = new SocketConnectionManager(
      config.socketUrl,
      '/packet_sniffer',
      handleStateChange
    );

    connectionManagerRef.current = manager;

    // Register event handlers
    Object.entries(eventHandlers.current).forEach(([eventType, handler]) => {
      manager.registerEventHandler(eventType, handler);
    });

    // Auto-connect
    manager.connect();

    return () => {
      manager.cleanup();
    };
  }, [handleStateChange]);

  // API methods
  const connect = useCallback(() => {
    connectionManagerRef.current?.connect();
  }, []);

  const disconnect = useCallback(() => {
    connectionManagerRef.current?.disconnect();
  }, []);

  const emitEvent = useCallback((eventType: string, data: any) => {
    connectionManagerRef.current?.emit(eventType, data);
  }, []);

  return {
    socket: connectionManagerRef.current?.['socket'] || null,
    isConnected: connectionState.isConnected,
    connectionError: connectionState.connectionError,
    retryAttempts: connectionState.retryAttempts,
    connect,
    disconnect,
    emitEvent,
  };
}

