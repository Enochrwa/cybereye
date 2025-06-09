import { useSelector } from "react-redux";
import { 
  ThreatDetection, 
  PhishingDetection, 
  FirewallEvent, 
  SystemStatus,
  NetworkTraffic,
  ThreatCount,
  HttpActivity,
  DnsActivity,
  PacketAnalysis,
  IPv6Activity,
  ThreatResponse,
  QuarantinedFile
} from "./types";

import { addHttpActivity } from "@/app/slices/socketSlice";
import { RootState } from "@/app/store";

export const useAlerts = () => {
  
  const httpActivity = useSelector((state: RootState) => state.socket.httpActivities)
  
  // if (httpActivity) {
  //   console.log('Http activity available: ', httpActivity);
  // }
    
  const threatLevelData = {
    current: "High" as "Critical" | "High" | "Medium" | "Low", 
    description: "Increased targeted phishing attempts and multiple brute-force attacks detected in the last 6 hours."
  }

  const activeThreatCounts: ThreatCount[] = [
    { severity: "Critical", count: 3 },
    { severity: "High", count: 12 },
    { severity: "Medium", count: 27 },
    { severity: "Low", count: 54 },
  ];

  const systemStatusData: SystemStatus[] = [
    {
      name: "Firewall",
      status: "Online",
      statusMessage: "Operating normally",
      statusSince: "2025-05-16T23:12:41Z"
    },
    {
      name: "Intrusion Detection",
      status: "Online",
      statusMessage: "Operating normally",
      statusSince: "2025-05-16T20:45:18Z"
    },
    {
      name: "Email Filter",
      status: "Online",
      statusMessage: "Operating normally",
      statusSince: "2025-05-17T01:30:25Z"
    },
    {
      name: "Log Analyzer",
      status: "Online",
      statusMessage: "Operating normally",
      statusSince: "2025-05-16T19:22:33Z"
    },
    {
      name: "Vulnerability Scanner",
      status: "Offline",
      statusMessage: "Scheduled maintenance",
      statusSince: "2025-05-17T03:00:00Z"
    }
  ];

  const networkTrafficData: NetworkTraffic[] = Array.from({ length: 24 }, (_, i) => {
    const baseValue = 2000 + Math.random() * 1000;
    const hasAnomaly = Math.random() > 0.9; // 10% chance of anomaly
    const anomalySpike = hasAnomaly ? Math.random() * 3000 : 0;
    
    const hours = 23 - i;
    const date = new Date();
    date.setHours(date.getHours() - hours);
    
    return {
      timestamp: date.toISOString(),
      packetsPerSecond: Math.round(baseValue + anomalySpike),
      hasAnomaly
    };
  });

  const recentCriticalAlerts: ThreatDetection[] = [
    {
      id: "T-CR-001",
      message: "Multiple failed admin login attempts detected",
      severity: "Critical",
      sourceIp: "103.42.91.118",
      targetSystem: "Authentication Server",
      timestamp: "2025-05-17T02:12:45Z",
      iocs: ["admin_login_bruteforce", "multiple_ip_rotation"],
      mitigationStatus: "Auto-mitigated"
    },
    {
      id: "T-CR-002",
      message: "Ransomware IOCs detected on endpoint",
      severity: "Critical",
      sourceIp: "192.168.1.155",
      targetSystem: "Finance-PC-15",
      timestamp: "2025-05-17T01:35:12Z",
      iocs: ["suspicious_encryption_activity", "known_ransom_file_pattern", "c2_communication_attempt"],
      mitigationStatus: "Requires Action"
    },
    {
      id: "T-CR-003",
      message: "Data exfiltration attempt blocked",
      severity: "Critical",
      sourceIp: "192.168.2.201",
      targetSystem: "HR-SERVER",
      timestamp: "2025-05-16T23:47:38Z",
      iocs: ["unusual_outbound_traffic_volume", "unauthorized_ftp_access"],
      mitigationStatus: "Auto-mitigated"
    },
    {
      id: "T-CR-004",
      message: "Malicious PowerShell execution detected",
      severity: "Critical",
      sourceIp: "192.168.3.25",
      targetSystem: "DEV-WORKSTATION-8",
      timestamp: "2025-05-16T21:23:10Z",
      iocs: ["obfuscated_powershell", "memory_injection_attempt"],
      mitigationStatus: "Requires Action"
    },
    {
      id: "T-CR-005",
      message: "Web application SQL injection attempt",
      severity: "Critical",
      sourceIp: "45.227.255.98",
      targetSystem: "Web Application Server",
      timestamp: "2025-05-16T20:15:33Z",
      iocs: ["sql_injection_pattern", "malformed_request"],
      mitigationStatus: "Auto-mitigated"
    }
  ];

  const threatDetections: ThreatDetection[] = [
    ...recentCriticalAlerts,
    {
      id: "T-HI-001",
      message: "Suspicious file download detected",
      severity: "High",
      sourceIp: "37.49.231.85",
      targetSystem: "Marketing-PC-3",
      timestamp: "2025-05-17T01:42:15Z",
      iocs: ["known_malware_hash", "suspicious_domain_access"],
      mitigationStatus: "Auto-mitigated"
    },
    {
      id: "T-HI-002",
      message: "Multiple failed VPN login attempts",
      severity: "High",
      sourceIp: "87.121.98.44",
      targetSystem: "VPN Gateway",
      timestamp: "2025-05-17T00:38:22Z",
      iocs: ["vpn_brute_force", "known_bad_ip"],
      mitigationStatus: "Auto-mitigated"
    },
    {
      id: "T-ME-001",
      message: "Unusual after-hours system access",
      severity: "Medium",
      sourceIp: "192.168.5.113",
      targetSystem: "CRM Access Portal",
      timestamp: "2025-05-16T22:15:30Z",
      iocs: ["after_hours_access", "unusual_data_query"],
      mitigationStatus: "Requires Action"
    },
    {
      id: "T-ME-002",
      message: "DNS requests to suspicious domain",
      severity: "Medium",
      sourceIp: "192.168.1.24",
      targetSystem: "Engineering-PC-7",
      timestamp: "2025-05-16T19:27:45Z",
      iocs: ["suspicious_dns_pattern", "domain_generation_algorithm"],
      mitigationStatus: "Auto-mitigated"
    },
    {
      id: "T-LO-001",
      message: "Outdated browser version detected",
      severity: "Low",
      sourceIp: "192.168.4.201",
      targetSystem: "Reception-PC-1",
      timestamp: "2025-05-16T18:55:12Z",
      iocs: ["vulnerable_browser_version"],
      mitigationStatus: "Requires Action"
    }
  ];

  const phishingDetections: PhishingDetection[] = [
    {
      url: "https://paypa1-secure-verification.com/login",
      confidenceScore: 96.8,
      categories: ["Phishing", "Brand Impersonation"],
      clickThroughRate: 0.12,
      detectionSource: "Automated",
      timestamp: "2025-05-17T02:27:19Z"
    },
    {
      url: "https://secure-docs-preview.onmcrsft.com/share/document",
      confidenceScore: 94.5,
      categories: ["Phishing", "Brand Impersonation", "Credential Theft"],
      clickThroughRate: 0.08,
      detectionSource: "Automated",
      timestamp: "2025-05-17T01:12:45Z"
    },
    {
      url: "https://important-tax-refund.irs-gov.eu/claim",
      confidenceScore: 98.2,
      categories: ["Phishing", "Government Impersonation"],
      clickThroughRate: 0.05,
      detectionSource: "User-reported",
      timestamp: "2025-05-17T00:38:22Z"
    },
    {
      url: "https://free-crypto-giveaway.site/claim-now",
      confidenceScore: 97.5,
      categories: ["Scam", "Cryptocurrency"],
      clickThroughRate: 0.14,
      detectionSource: "Automated",
      timestamp: "2025-05-16T23:41:10Z"
    },
    {
      url: "https://download-update.adobe-player.org/update",
      confidenceScore: 93.7,
      categories: ["Malware", "Brand Impersonation"],
      clickThroughRate: null,
      detectionSource: "Automated",
      timestamp: "2025-05-16T22:15:38Z"
    },
    {
      url: "https://it-helpdesk-ticket.company-support.co/password-reset",
      confidenceScore: 89.5,
      categories: ["Phishing", "Spear Phishing"],
      clickThroughRate: 0.22,
      detectionSource: "User-reported",
      timestamp: "2025-05-16T21:09:14Z"
    }
  ];

  const firewallEvents: FirewallEvent[] = [
    {
      ipAddress: "45.137.21.9",
      action: "Blocked",
      reason: "Block SSH brute force attempt",
      ruleTrigger: "Rate limit exceeded: SSH connection attempts",
      geoLocation: "Russia",
      timestamp: "2025-05-17T02:17:34Z"
    },
    {
      ipAddress: "103.42.91.118",
      action: "Blocked",
      reason: "Suspicious login pattern",
      ruleTrigger: "Multiple failed admin logins",
      geoLocation: "China",
      timestamp: "2025-05-17T02:12:40Z"
    },
    {
      ipAddress: "91.195.240.117",
      action: "Blocked",
      reason: "Known botnet IP address",
      ruleTrigger: "Threat intelligence match",
      geoLocation: "Netherlands",
      timestamp: "2025-05-17T01:55:27Z"
    },
    {
      ipAddress: "23.106.223.55",
      action: "Blocked",
      reason: "Attempted directory traversal attack",
      ruleTrigger: "Web application firewall pattern match",
      geoLocation: "United States",
      timestamp: "2025-05-17T01:42:19Z"
    },
    {
      ipAddress: "192.168.15.27",
      action: "Allowed",
      reason: "Internal network communication",
      ruleTrigger: "Intra-network traffic policy",
      geoLocation: "Internal",
      timestamp: "2025-05-17T01:35:45Z"
    },
    {
      ipAddress: "18.169.52.38",
      action: "Allowed",
      reason: "Authorized cloud provider",
      ruleTrigger: "Whitelist match",
      geoLocation: "United Kingdom",
      timestamp: "2025-05-17T01:28:12Z"
    },
    {
      ipAddress: "87.121.98.44",
      action: "Blocked",
      reason: "VPN brute force attempt",
      ruleTrigger: "Rate limit exceeded: VPN connection attempts",
      geoLocation: "Ukraine",
      timestamp: "2025-05-17T00:38:22Z"
    },
    {
      ipAddress: "185.220.101.33",
      action: "Blocked",
      reason: "Tor exit node",
      ruleTrigger: "Connection from Tor network",
      geoLocation: "Germany",
      timestamp: "2025-05-16T23:51:08Z"
    }
  ];

  // Mock data for HTTP activity monitoring
  const httpActivities: HttpActivity[] = [
    {
      id: "http-001",
      timestamp: "2025-05-16T15:32:45Z",
      sourceIp: "192.168.1.45",
      destinationIp: "203.0.113.42",
      method: "POST",
      path: "/api/v1/users/login",
      statusCode: 200,
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      referrer: "https://example.com/login",
      contentType: "application/json",
      missingSecurityHeaders: ["Content-Security-Policy"],
      injectionDetected: false,
      beaconingIndicators: false,
      threatScore: 15
    },
    {
      id: "http-002",
      timestamp: "2025-05-16T15:30:12Z",
      sourceIp: "192.168.1.67",
      destinationIp: "203.0.113.42",
      method: "GET",
      path: "/admin/config?debug=true&access=all",
      statusCode: 403,
      userAgent: "curl/7.68.0",
      referrer: null,
      contentType: "text/html",
      missingSecurityHeaders: ["X-Content-Type-Options", "X-Frame-Options"],
      injectionDetected: true,
      beaconingIndicators: false,
      threatScore: 78
    },
    {
      id: "http-003",
      timestamp: "2025-05-16T15:28:56Z",
      sourceIp: "203.0.113.100",
      destinationIp: "192.168.1.10",
      method: "GET",
      path: "/wp-admin/install.php",
      statusCode: 404,
      userAgent: "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)",
      referrer: null,
      contentType: "text/html",
      missingSecurityHeaders: [],
      injectionDetected: false,
      beaconingIndicators: true,
      threatScore: 65
    },
    {
      id: "http-004",
      timestamp: "2025-05-16T15:25:34Z",
      sourceIp: "192.168.1.200",
      destinationIp: "203.0.113.42",
      method: "POST",
      path: "/api/v1/data",
      statusCode: 500,
      userAgent: "Apache-HttpClient/4.5.13 (Java/11.0.12)",
      referrer: null,
      contentType: "application/json",
      missingSecurityHeaders: ["Strict-Transport-Security"],
      injectionDetected: false,
      beaconingIndicators: false,
      threatScore: 45
    },
    {
      id: "http-005",
      timestamp: "2025-05-16T15:22:18Z",
      sourceIp: "192.168.1.45",
      destinationIp: "198.51.100.234",
      method: "GET",
      path: "/images/logo.png",
      statusCode: 200,
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
      referrer: "https://example.com/home",
      contentType: "image/png",
      missingSecurityHeaders: [],
      injectionDetected: false,
      beaconingIndicators: false,
      threatScore: 5
    }
  ];

  // Mock data for DNS activity monitoring
  const dnsActivities: DnsActivity[] = [
    {
      id: "dns-001",
      timestamp: "2025-05-16T15:33:12Z",
      domain: "example.com",
      recordType: "A",
      queryResult: "203.0.113.42",
      ttl: 3600,
      possibleDGA: false,
      matchedThreatIntel: false,
      clientIp: "192.168.1.45"
    },
    {
      id: "dns-002",
      timestamp: "2025-05-16T15:31:48Z",
      domain: "a3fg92k1jd02.evil-domain.com",
      recordType: "A",
      queryResult: "198.51.100.234",
      ttl: 60,
      possibleDGA: true,
      matchedThreatIntel: true,
      clientIp: "192.168.1.67"
    },
    {
      id: "dns-003",
      timestamp: "2025-05-16T15:30:22Z",
      domain: "cdn.example.com",
      recordType: "CNAME",
      queryResult: "cdn-edge.cloudprovider.com",
      ttl: 14400,
      possibleDGA: false,
      matchedThreatIntel: false,
      clientIp: "192.168.1.45"
    },
    {
      id: "dns-004",
      timestamp: "2025-05-16T15:28:59Z",
      domain: "mail.example.com",
      recordType: "MX",
      queryResult: "mail-server.example.com",
      ttl: 86400,
      possibleDGA: false,
      matchedThreatIntel: false,
      clientIp: "192.168.1.10"
    },
    {
      id: "dns-005",
      timestamp: "2025-05-16T15:27:31Z",
      domain: "x82jd72hsk219sd.dynamic-domain.net",
      recordType: "A",
      queryResult: "203.0.113.100",
      ttl: 120,
      possibleDGA: true,
      matchedThreatIntel: false,
      clientIp: "192.168.1.67"
    }
  ];

  // Mock data for packet analysis
  const packetAnalyses: PacketAnalysis[] = [
    {
      id: "pkt-001",
      timestamp: "2025-05-16T15:33:45Z",
      protocol: "TCP",
      sourceIp: "192.168.1.45",
      destinationIp: "203.0.113.42",
      sourcePort: 54321,
      destinationPort: 443,
      payloadSize: 1024,
      highEntropy: false,
      suspiciousPatterns: false,
      geoLocationSource: "United States",
      geoLocationDestination: "Germany",
      anomalyDetected: null
    },
    {
      id: "pkt-002",
      timestamp: "2025-05-16T15:32:12Z",
      protocol: "UDP",
      sourceIp: "203.0.113.100",
      destinationIp: "192.168.1.10",
      sourcePort: 53,
      destinationPort: 52342,
      payloadSize: 512,
      highEntropy: true,
      suspiciousPatterns: true,
      geoLocationSource: "Russia",
      geoLocationDestination: "United States",
      anomalyDetected: "Port scan detected"
    },
    {
      id: "pkt-003",
      timestamp: "2025-05-16T15:30:58Z",
      protocol: "TCP",
      sourceIp: "192.168.1.67",
      destinationIp: "198.51.100.234",
      sourcePort: 58932,
      destinationPort: 80,
      payloadSize: 768,
      highEntropy: false,
      suspiciousPatterns: false,
      geoLocationSource: "United States",
      geoLocationDestination: "France",
      anomalyDetected: null
    },
    {
      id: "pkt-004",
      timestamp: "2025-05-16T15:29:30Z",
      protocol: "ICMP",
      sourceIp: "192.168.1.200",
      destinationIp: "192.168.1.1",
      sourcePort: 0,
      destinationPort: 0,
      payloadSize: 64,
      highEntropy: false,
      suspiciousPatterns: false,
      geoLocationSource: "United States",
      geoLocationDestination: "United States",
      anomalyDetected: null
    },
    {
      id: "pkt-005",
      timestamp: "2025-05-16T15:28:14Z",
      protocol: "TCP",
      sourceIp: "203.0.113.42",
      destinationIp: "192.168.1.45",
      sourcePort: 443,
      destinationPort: 54321,
      payloadSize: 2048,
      highEntropy: true,
      suspiciousPatterns: false,
      geoLocationSource: "Germany",
      geoLocationDestination: "United States",
      anomalyDetected: null
    }
  ];

  // Mock data for IPv6 activity
  const ipv6Activities: IPv6Activity[] = [
    {
      id: "ipv6-001",
      timestamp: "2025-05-16T15:34:12Z",
      sourceIPv6: "2001:db8:3333:4444:5555:6666:7777:8888",
      destinationIPv6: "2001:db8:1111:2222:3333:4444:5555:6666",
      protocol: "TCP",
      payloadSize: 1024,
      baselineDeviation: 12.5,
      tunneled: false
    },
    {
      id: "ipv6-002",
      timestamp: "2025-05-16T15:32:48Z",
      sourceIPv6: "2001:db8:85a3::8a2e:370:7334",
      destinationIPv6: "2001:db8:3333:4444:5555:6666:7777:8888",
      protocol: "UDP",
      payloadSize: 4096,
      baselineDeviation: 78.3,
      tunneled: true
    },
    {
      id: "ipv6-003",
      timestamp: "2025-05-16T15:31:22Z",
      sourceIPv6: "2001:db8:1111:2222:3333:4444:5555:6666",
      destinationIPv6: "2001:db8:85a3::8a2e:370:7334",
      protocol: "ICMP6",
      payloadSize: 128,
      baselineDeviation: 5.2,
      tunneled: false
    },
    {
      id: "ipv6-004",
      timestamp: "2025-05-16T15:29:57Z",
      sourceIPv6: "2001:db8:3333:4444:5555:6666:7777:8888",
      destinationIPv6: "2001:db8:1111:2222:3333:4444:5555:6666",
      protocol: "TCP",
      payloadSize: 2048,
      baselineDeviation: 32.7,
      tunneled: false
    },
    {
      id: "ipv6-005",
      timestamp: "2025-05-16T15:28:36Z",
      sourceIPv6: "2001:db8:85a3::8a2e:370:7334",
      destinationIPv6: "2001:db8:1111:2222:3333:4444:5555:6666",
      protocol: "UDP",
      payloadSize: 512,
      baselineDeviation: 18.4,
      tunneled: true
    }
  ];

  // Mock data for threat responses
  const threatResponses: ThreatResponse[] = [
    {
      id: "resp-001",
      timestamp: "2025-05-16T15:35:22Z",
      action: "Blocked IP",
      target: "203.0.113.100",
      status: "Success",
      details: "Added to firewall blocklist for 24 hours"
    },
    {
      id: "resp-002",
      timestamp: "2025-05-16T15:34:15Z",
      action: "Quarantined File",
      target: "/var/www/uploads/document.pdf",
      status: "Success",
      details: "File contained malicious JavaScript"
    },
    {
      id: "resp-003",
      timestamp: "2025-05-16T15:32:47Z",
      action: "Terminated Process",
      target: "PID 4528 (suspicious.exe)",
      status: "Success",
      details: "Process was attempting to modify system files"
    },
    {
      id: "resp-004",
      timestamp: "2025-05-16T15:30:12Z",
      action: "Reset User Password",
      target: "admin@example.com",
      status: "Failure",
      details: "Failed to connect to authentication server"
    },
    {
      id: "resp-005",
      timestamp: "2025-05-16T15:28:55Z",
      action: "Removed Malicious Registry Key",
      target: "HKLM\\SOFTWARE\\Malware",
      status: "Success",
      details: "Registry key was causing system startup issues"
    }
  ];

  // Mock data for quarantined files
  const quarantinedFiles: QuarantinedFile[] = [
    {
      id: "quar-001",
      timestamp: "2025-05-16T15:34:15Z",
      filePath: "/var/www/uploads/document.pdf",
      fileHash: "5f4dcc3b5aa765d61d8327deb882cf99",
      reason: "Embedded malicious JavaScript",
      originalProcess: "apache2"
    },
    {
      id: "quar-002",
      timestamp: "2025-05-16T15:31:42Z",
      filePath: "C:\\Users\\Admin\\Downloads\\invoice.exe",
      fileHash: "e10adc3949ba59abbe56e057f20f883e",
      reason: "Known malware signature",
      originalProcess: "chrome.exe"
    },
    {
      id: "quar-003",
      timestamp: "2025-05-16T15:30:28Z",
      filePath: "/home/user/suspicious-script.sh",
      fileHash: "25f9e794323b453885f5181f1b624d0b",
      reason: "Attempts to modify system files",
      originalProcess: "bash"
    },
    {
      id: "quar-004",
      timestamp: "2025-05-16T15:28:13Z",
      filePath: "C:\\Windows\\System32\\drivers\\etc\\hosts",
      fileHash: "d8578edf8458ce06fbc5bb76a58c5ca4",
      reason: "Unauthorized modification",
      originalProcess: "unknown.exe"
    },
    {
      id: "quar-005",
      timestamp: "2025-05-16T15:26:59Z",
      filePath: "/var/log/auth.log",
      fileHash: "5d41402abc4b2a76b9719d911017c592",
      reason: "Log tampering detected",
      originalProcess: "root"
    }
  ];

  return {
    threatLevelData,
    activeThreatCounts,
    networkTrafficData,
    systemStatusData,
    threatDetections,
    recentCriticalAlerts,
    phishingDetections,
    firewallEvents,
    httpActivities,
    dnsActivities,
    packetAnalyses,
    ipv6Activities,
    threatResponses,
    quarantinedFiles,

  }
}