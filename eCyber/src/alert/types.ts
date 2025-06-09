
export type ThreatSeverity = "Critical" | "High" | "Medium" | "Low";

export interface ThreatDetection {
  id: string;
  message: string;
  severity: ThreatSeverity;
  sourceIp: string;
  targetSystem: string;
  timestamp: string;
  iocs: string[];
  mitigationStatus: "Auto-mitigated" | "Requires Action";
}

export interface PhishingDetection {
  url: string;
  confidenceScore: number;
  categories: string[];
  clickThroughRate: number | null;
  detectionSource: "User-reported" | "Automated";
  timestamp: string;
}

export interface FirewallEvent {
  ipAddress: string;
  action: "Blocked" | "Allowed";
  reason: string;
  ruleTrigger: string;
  geoLocation: string;
  timestamp: string;
}

export interface SystemStatus {
  name: string;
  status: "Online" | "Offline";
  statusMessage: string;
  statusSince: string;
}

export interface NetworkTraffic {
  timestamp: string;
  packetsPerSecond: number;
  hasAnomaly: boolean;
}

export interface ThreatCount {
  severity: ThreatSeverity;
  count: number;
}

// New interfaces for the additional monitoring components

export interface HttpActivity {
  id: string;
  timestamp: string;
  sourceIp: string;
  destinationIp: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "OPTIONS" | "HEAD";
  path: string;
  statusCode: number;
  userAgent: string;
  referrer: string | null;
  contentType: string | null;
  missingSecurityHeaders: string[];
  injectionDetected: boolean;
  beaconingIndicators: boolean;
  threatScore: number; // 0-100
}

export interface DnsActivity {
  id: string;
  timestamp: string;
  domain: string;
  recordType: "A" | "AAAA" | "MX" | "CNAME" | "TXT" | "NS" | "PTR" | "SRV";
  queryResult: string;
  ttl: number;
  possibleDGA: boolean;
  matchedThreatIntel: boolean;
  clientIp: string;
}

export interface PacketAnalysis {
  id: string;
  timestamp: string;
  protocol: "TCP" | "UDP" | "ICMP" | "OTHER";
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  payloadSize: number;
  highEntropy: boolean;
  suspiciousPatterns: boolean;
  geoLocationSource: string;
  geoLocationDestination: string;
  anomalyDetected: string | null;
}

export interface IPv6Activity {
  id: string;
  timestamp: string;
  sourceIPv6: string;
  destinationIPv6: string;
  protocol: string;
  payloadSize: number;
  baselineDeviation: number;
  tunneled: boolean;
}

export interface ThreatResponse {
  id: string;
  timestamp: string;
  action: string;
  target: string;
  status: "Success" | "Failure";
  details: string;
}

export interface QuarantinedFile {
  id: string;
  timestamp: string;
  filePath: string;
  fileHash: string;
  reason: string;
  originalProcess: string;
}
