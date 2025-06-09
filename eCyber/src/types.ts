/ Log type interfaces

export interface FirewallLog {
  id: number;
  timestamp: string;
  action: "ALLOW" | "DENY";
  source_ip: string;
  destination_ip: string;
  protocol: string;
  rule_id: string;
}

export interface NetworkEventLog {
  id: number;
  timestamp: string;
  event_type: string;
  source_ip: string;
  source_mac: string;
  destination_ip: string;
  destination_port: number;
  protocol: string;
  length: number;
  application: string;
  payload: string;
  geo: {
    country: string;
    city: string;
    isp: string;
  };
}

export interface ThreatLog {
  id: number;
  timestamp: string;
  event_type: string;
  src_ip: string;
  src_mac: string;
  dest_ip: string;
  port: number;
  protocol: string;
  packet_size: number;
  service: string;
  message: string;
  geo: {
    country: string;
    city: string;
    isp: string;
  };
}

export interface SystemLog {
  id: number;
  timestamp: string;
  component: string;
  level: string;
  message: string;
  details: {
    method?: string;
    endpoint?: string;
    error_code?: string;
    attempts?: number;
    [key: string]: any;
  };
  user_id?: number;
  source_ip?: string;
  request_id?: string;
  resolved?: boolean;
  resolution_notes?: string | null;
  stack_trace?: string;
  duration_ms?: number;
}

export interface MonitoringLog {
  id: number;
  type: string;
  level: string;
  message: string;
  source: string;
  details: {
    [key: string]: any;
  };
  timestamp: string;
  action: string;
  user_id?: number;
  user?: {
    id: number;
    username: string;
    email: string;
  };
}

export interface FirewallRule {
  id: number;
  name: string;
  action: string;
  direction: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface IDSRule {
  id: number;
  name: string;
  description: string;
  action: string;
  protocol: string;
  source_ip: string;
  source_port: string;
  destination_ip: string;
  destination_port: string;
  pattern: string;
  content_modifiers: {
    nocase: boolean;
    depth: number;
    offset: number;
    [key: string]: any;
  };
  threshold: number;
  window: number;
  active: boolean;
  severity: string;
  created_at: string;
  updated_at: string;
}
