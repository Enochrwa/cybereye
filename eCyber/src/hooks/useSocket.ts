// frontend/src/hooks/useSocket.ts
import { useEffect, useCallback, useState, useRef } from 'react';
import { io, Socket } from 'socket.io-client';
import { throttle } from 'lodash';
import { useDispatch } from 'react-redux';

// ==================== Event export interfaces ====================
export interface ThreatData { id: string; message: string; severity: 'low' | 'medium' | 'high'; }
export interface PhishingData { url: string; confidence: number; }
export interface TrainingProgress { epoch: number; accuracy: number; loss: number; }
export interface NetworkAnomaly { type: string; packetCount: number; }
export interface AccessData { user: string; sourceIp: string; }
export interface FirewallData { rule: string; action: 'block' | 'allow'; }
export interface UrlClassification { url: string; category: string; confidence: number; }
export interface ServiceStatus { name: string; status: 'running' | 'stopped'; uptime?: number; }
export interface Alert { message: string; timestamp: string; }
export interface HttpActivity { endpoint: string; method: string; statusCode: number; }
export interface DnsQuery { domain: string; recordType: string; }
export interface ErrorData { error: string; code?: number; }
export interface SshConnection { ip: string; user?: string; }
export interface FirewallEvent { ip: string; type: 'block' | 'allow'; reason: string; }
export interface Rule { id: string; name: string; description: string; }
export interface SystemStats { cpu: number; memory: number; network: number; }
export interface SystemStatus { online: boolean; services: string[]; }
export interface IPv6Activity { source: string; destination: string; payloadSize: number; }
export interface CriticalAlert { type: string; source: string; mitigation: string; }
export interface SystemTelemetry { cpu: number; memory: number; processes: ProcessInfo[]; }
export interface ThreatResponse { action: string; target: string; success: boolean; }
export interface ProcessInspection { pid: number; name: string; suspicious: boolean; }
export interface ConnectionAnalysis { protocol: string; count: number; riskScore: number; }
export interface FileQuarantined { path: string; hash: string; reason: string; }
export interface SystemSnapshot { timestamp: string; metrics: SystemStats; }
export interface ProcessInfo { pid: number; name: string; cpu: number; memory: number; }
export interface AnalysisError { data: any}
export interface PacketMetadata {
  timestamp: number;
  src_ip: string | null;
  dst_ip: string | null;
  protocol: number | null;
  length: number;
  src_port: number | null;
  dst_port: number | null;
  payload: string | null;
}

// ==================== Event Type Definitions ====================
export type SocketEvent =
  | { type: 'threat_detected'; data: ThreatData }
  | { type: 'analysis_error'; data: AnalysisError}
  | { type: 'network_metrics'; data: any }
  | { type: 'phishing_link_detected'; data: PhishingData }
  | { type: 'training_progress'; data: TrainingProgress }
  | { type: 'training_completed'; data: null }
  | { type: 'network_anomaly'; data: NetworkAnomaly }
  | { type: 'unauthorized_access'; data: AccessData }
  | { type: 'firewall_blocked'; data: FirewallData }
  | { type: 'url_classification_result'; data: UrlClassification }
  | { type: 'service_status'; data: ServiceStatus }
  | { type: 'user_alert'; data: Alert }
  | { type: 'security_alert'; data: Alert }
  | { type: 'http_activity'; data: HttpActivity }
  | { type: 'dns_activity'; data: DnsQuery }
  | { type: 'database_error'; data: ErrorData }
  | { type: 'ssh_connection'; data: SshConnection }
  | { type: 'firewall_event'; data: FirewallEvent }
  | { type: 'detection_error'; data: ErrorData }
  | { type: 'rules_updated'; data: { count: number } }
  | { type: 'get_rules'; data: Rule[] }
  | { type: 'system_stats'; data: SystemStats }
  | { type: 'system_error'; data: ErrorData }
  | { type: 'system_status'; data: SystemStatus }
  | { type: 'ipv6_activity'; data: IPv6Activity }
  | { type: 'critical_alert'; data: CriticalAlert }
  | { type: 'system_telemetry'; data: SystemTelemetry }
  | { type: 'threat_response'; data: ThreatResponse }
  | { type: 'process_inspection'; data: ProcessInspection }
  | { type: 'connection_analysis'; data: ConnectionAnalysis }
  | { type: 'file_quarantined'; data: FileQuarantined }
  | { type: 'system_snapshot'; data: SystemSnapshot }
  | { type: 'packet_data'; data: PacketMetadata };

// ==================== Hook Return Type ====================
export interface UseSocketReturn {
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

// ==================== Event Handlers Configuration ====================


// ==================== Socket Event Types ====================
const ALL_SOCKET_EVENTS: SocketEvent['type'][] = [
  'threat_detected', 'network_metrics', 'phishing_link_detected',
  'training_progress', 'training_completed', 'network_anomaly',
  'unauthorized_access', 'firewall_blocked', 'url_classification_result',
  'service_status', 'user_alert', 'security_alert', 'http_activity',
  'dns_activity', 'database_error', 'ssh_connection', 'firewall_event',
  'detection_error', 'rules_updated', 'get_rules', 'system_stats',
  'system_error', 'system_status', 'ipv6_activity', 'critical_alert',
  'system_telemetry', 'threat_response', 'process_inspection',
  'connection_analysis', 'file_quarantined', 'system_snapshot', 'packet_data'
];

// ==================== Main Hook Implementation ====================
export default function useSocket(): UseSocketReturn {
  
  const dispatch = useDispatch();

  const EVENT_HANDLERS_CONFIG = {
    // High-priority security events
    'threat_detected': (data: ThreatData) => console.warn('⚠️ Threat Detected:', data),
    'critical_alert': (data: CriticalAlert) => console.error('🔥 Critical Alert:', data),
    'unauthorized_access': (data: AccessData) => console.warn('🚨 Unauthorized Access:', data),
    'phishing_link_detected': (data: PhishingData) => console.warn('🎣 Phishing Link:', data),
    
    // System monitoring events
    'system_error': (data: ErrorData) => console.error('❌ System Error:', data),
    'system_status': (data: SystemStatus) => console.info('🖥️ System Status:', data),
    'service_status': (data: ServiceStatus) => console.info('🛠️ Service Status:', data),
    'analysis_error': (data: AnalysisError) => console.log("Analysis Error", data),
    
    // Network events
    'network_anomaly': throttle((data: NetworkAnomaly) =>
      console.log('🌐 Network Anomaly:', data), 1000),
    'firewall_event': (data: FirewallEvent) => console.info('🔥 Firewall Event:', data),
    'packet_data': (data: PacketMetadata) => console.debug('📦 Packet Data:', data),
    
    // Training events
    'training_progress': (data: TrainingProgress) => console.info('🏋️ Training Progress:', data),
    'training_completed': () => console.info('✅ Training Completed'),
    
    
    'system_stats': (data: SystemStats) => console.debug('📈 System Stats:', data),
    
    // Default handler for unconfigured events
    'default': (type: string, data: any) => console.log(`ℹ️ Event: ${type}`, data)
  };
  

  const socketRef = useRef<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const initialized = useRef(false);
  const handlers = useRef(new Map<SocketEvent['type'], Set<Function>>());

  // ==================== Event Handler ====================
  const handleEvent = useCallback((event: SocketEvent) => {
    // Call registered handlers first
    const eventHandlers = handlers.current.get(event.type);
    eventHandlers?.forEach(handler => handler(event.data));

    // Then call configured handlers
    const configuredHandler = EVENT_HANDLERS_CONFIG[event.type] || 
      ((data: any) => EVENT_HANDLERS_CONFIG.default(event.type, data));
    configuredHandler(event.data);
  }, []);

  // ==================== Connection Management ====================
  const connect = useCallback(() => {
    if (socketRef.current?.connected || initialized.current) return;

    const newSocket = io('http://127.0.0.1:8000', {
      path: '/socket.io',             // Matches your FastAPI mount
      transports: ['websocket'],
      reconnectionAttempts: 5,
      reconnectionDelay: 3000,
      autoConnect: false,
      upgrade: false,
    });

    

    // Connection lifecycle handlers
    newSocket
      .on('connect', () => {
        setIsConnected(true);
        setConnectionError(null);
        console.log("✅ Socket connected to:", newSocket.nsp);
      })
      .on('connect_error', (err) => {
        setConnectionError(err.message);
        console.error('❌ Connection Error:', err);
      })
      .on('disconnect', () => {
        setIsConnected(false);
        console.warn('⚠️ Socket Disconnected');
      });

    // Register all event listeners
    ALL_SOCKET_EVENTS.forEach(event => {
      newSocket.on(event, (data: any) => handleEvent({ type: event, data } as SocketEvent));
    });

    newSocket.connect();
    socketRef.current = newSocket;
    initialized.current = true;
  }, [handleEvent]);

  // ==================== Disconnection Handler ====================
  const disconnect = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.disconnect();
      socketRef.current = null;
      initialized.current = false;
      setIsConnected(false);
      console.log('🔌 Socket Disconnected');
    }
  }, []);

  // ==================== Event Emission ====================
  const emitEvent = useCallback<UseSocketReturn['emitEvent']>((type, data) => {
    if (socketRef.current?.connected) {
      socketRef.current.emit(type, data);
    } else {
      console.warn('⚠️ Cannot emit event - socket not connected');
    }
  }, []);

  // ==================== Subscription Management ====================
  const subscribe = useCallback<UseSocketReturn['subscribe']>((eventType, handler) => {
    if (!handlers.current.has(eventType)) {
      handlers.current.set(eventType, new Set());
    }
    handlers.current.get(eventType)?.add(handler);
  }, []);

  const unsubscribe = useCallback<UseSocketReturn['unsubscribe']>((eventType, handler) => {
    handlers.current.get(eventType)?.delete(handler);
  }, []);

  // ==================== Lifecycle Management ====================
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
}