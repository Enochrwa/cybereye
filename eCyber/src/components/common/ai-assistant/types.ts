
import { ReactNode } from 'react';
import { LucideIcon } from 'lucide-react';

export interface Message {
  id: number;
  text: string;
  sender: 'user' | 'ai';
  timestamp: Date;
  isLoading?: boolean;
  isTyping?: boolean;
  category?: string; // Updated to allow any string, including knowledge base IDs
  tags?: string[];
  liked?: boolean;
}

export interface SecurityTopic {
  id: string;
  title: string;
  description: string;
  icon: LucideIcon;
}

export interface AIAssistantProps {
  className?: string;
}

export interface TypingIndicatorProps {
  className?: string;
}

// Attack Simulation Types
export type AttackType = 
  | 'ddos' 
  | 'port-scan' 
  | 'sql-injection' 
  | 'phishing' 
  | 'unauthorized-access' 
  | 'malware' 
  | 'data-exfiltration' 
  | 'behavioral-deviation';

export interface SimulationStatus {
  active: boolean;
  progress: number;
  alerts: SimulationAlert[];
  timestamp: Date | null;
}

export interface SimulationAlert {
  id: string;
  type: AttackType;
  message: string;
  severity: 'info' | 'warning' | 'critical';
  timestamp: Date;
  details?: Record<string, any>;
  resolved?: boolean;
}

export interface NetworkTraffic {
  timestamp: Date;
  packetsPerSecond: number;
  protocols: Record<string, number>;
  suspiciousFlags: number;
  sourceIp?: string;
  targetIp?: string;
}

export interface ScanResult {
  id: string;
  timestamp: Date;
  threatsDetected: number;
  cleanedFiles: number;
  blockedIPs: string[];
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface HoneypotLog {
  id: string;
  timestamp: Date;
  attackerIP: string;
  commands?: string[];
  payloads?: string[];
  honeypotType: 'ssh' | 'http' | 'ftp' | 'smb';
  threatLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface DomainInfo {
  domain: string;
  status: 'safe' | 'suspicious' | 'blocked';
  age?: number; // in days
  registrar?: string;
  riskScore?: number; // 0-100
  isPhishing?: boolean;
}

export interface SystemMetrics {
  timestamp: Date;
  cpuUsage: number;
  memoryUsage: number;
  activeProcesses: number;
  suspiciousBehaviors: number;
}

export interface Vulnerability {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cveId?: string;
  affectedService?: string;
  remediation?: string;
}
