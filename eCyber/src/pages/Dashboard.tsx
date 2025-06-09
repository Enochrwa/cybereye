import React, { useState, useEffect } from 'react';
import { 
  Activity, 
  Shield, 
  Users, 
  Globe, 
  Database,
  AlertOctagon,
  Bell,
  Info,
  ArrowRight
} from 'lucide-react';
import { useLocation, useNavigate } from 'react-router-dom';

import { RootState } from '../app/store'

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { cn } from "@/lib/utils";
// import Header from '../components/layout/Header';
// import Sidebar from '../components/layout/Sidebar';
import MetricsCard from '../components/dashboard/MetricsCard';
import ThreatMap from '../components/dashboard/ThreatMap';
import ActivityStream from '../components/dashboard/ActivityStream';
import AIAssistant from '../components/common/AIAssistant';
import { useTelemetrySocket } from '@/components/live-system/lib/socket';
import { useSelector } from 'react-redux';
import { Alert as StoreAlert } from '@/hooks/usePacketSnifferSocket'; // Renaming to avoid conflict with local types if any
import { HttpActivity as StoreHttpActivity } from '@/hooks/usePacketSnifferSocket';
import { DnsActivityData as StoreDnsActivityData } from '@/hooks/usePacketSnifferSocket';
import  ActivityItemProps  from '../components/dashboard/ActivityStream'; // Import the prop type
import { useDeepCompareEffect } from 'use-deep-compare';
import AnomalyInsightsSection from '@/components/dashboard/AnomalyInsightsSection'; // Added import
import HttpActivityView from '../components/dashboard/HttpActivityView'; // Import HTTP Log View
import DnsActivityView from '../components/dashboard/DnsActivityView';   // Import DNS Log View
import { UserList } from '@/components/dashboard/UserList'; // Import the new component

// Mock data for activity stream - REMOVED

// import { EmergingThreatDisplay } from './Threats'; // Assuming Threats.tsx exports this type
// Or define locally if not exported / for clarity in Dashboard context
interface DashboardEmergingThreat {
  id: string;
  name: string;
  severity: "critical" | "warning" | "info" | "unknown"; // Matched to emergingThreats mapping below
  type: string;
  details: string;
  affectedSystems: string[];
  timestamp: Date;
  detectionCount?: number; // Made optional as it's not directly from API
}

// Backend EmergingThreat structure (for reference during mapping)
interface BackendEmergingThreat {
  type: string;
  id?: string; 
  summary?: string; 
  indicator?: string; 
  indicator_type?: string; 
  threat_type?: string; 
  source: string;
  published?: string; 
  last_seen?: string; 
}


// Simulated emerging threat data - To be replaced by API call below
// const emergingThreatsMock = [ ... ]; // Removed

// Map routes to tab values
const threatsMap = [{
    name: "DragonFly APT",
    severity: "critical" as const,
    type: "Advanced Persistent Threat",
    details: "Targeting energy sector with spear-phishing campaign",
    affectedSystems: ["Windows Server 2019", "VMWare ESXi"],
    timestamp: new Date(Date.now() - 75 * 60 * 1000), // Will be string from store
    detectionCount: 3
  },
  {
    id: "threat2",
    name: "CosmicRaven Ransomware",
    severity: "critical" as const,
    type: "Ransomware",
    details: "New variant with enhanced encryption and data exfiltration",
    affectedSystems: ["Linux", "Windows"],
    timestamp: new Date(Date.now() - 120 * 60 * 1000),
    detectionCount: 1
  },
  {
    id: "threat3",
    name: "ShadowScript Injection",
    severity: "warning" as const,
    type: "Web Vulnerability",
    details: "Targeting Node.js applications with prototype pollution",
    affectedSystems: ["Web Services", "Node.js"],
    timestamp: new Date(Date.now() - 240 * 60 * 1000),
    detectionCount: 8
  }
];

// Map routes to tab values
const routeToTabMap = {
  '/dashboard': 'overview',
  '/threats': 'threat-intel',
  '/network': 'network',
  '/logs': 'logs',
  '/models': 'models',
  '/users': 'users',
  '/settings': 'settings'
};

const Dashboard = () => {
  const location = useLocation();
  const navigate = useNavigate();

  


  const networkVolume = useSelector((state:RootState) => state.networkVolume.networkVolume);

  const { getSocket, isOfflineMode } = useTelemetrySocket();
  
  // State for last updated time and dynamic data
  const [offline, setOffline] = useState(isOfflineMode());
  const [lastUpdated, setLastUpdated] = useState(new Date()); // Will be updated by real-time data presence
  
  // Redux state selectors
  const securityAlerts = useSelector((state: RootState) => state.realtimeData?.recentAlerts);
  const threatDetections = useSelector((state: RootState) => state.realtimeData?.threatDetectionsData);
  const httpActivities = useSelector((state: RootState) => state.socket?.httpActivities || []);
  const dnsActivities = useSelector((state: RootState) => state.realtimeData?.dnsActivities || []);
  const firewallEvents = useSelector((state: RootState) => state.realtimeData?.firewallEventsData || []);
  const tcpActivities = useSelector((state: RootState) => state.socket?.tcpActivities || []);
  const udpActivities = useSelector((state: RootState) => state.socket?.udpActivities || []);
  const icmpActivities = useSelector((state: RootState) => state.socket?.icmpActivities || []);
  const arpActivities = useSelector((state: RootState) => state.socket?.arpActivities || []);
  const payloadAnalysisEvents = useSelector((state: RootState) => state.socket?.payloadAnalysisEvents || []);
  const behaviorAnalysisEvents = useSelector((state: RootState) => state.socket?.behaviorAnalysisEvents || []);
  // const systemStats = useSelector((state: RootState) => state.realtimeData.systemStats); // For later use if needed

  // Local state derived from Redux or for UI
  const [currentThreatMetrics, setCurrentThreatMetrics] = useState({ critical: 0, warning: 0, info: 0, blocked: 0 });
  const [isAnomalyDetected, setIsAnomalyDetected] = useState(false);
  const [lastAnomalyToastTime, setLastAnomalyToastTime] = useState(0); // To prevent toast spam
  const [networkStats, setNetworkStats] = useState<any>(null); // Define a proper type later
  const [isLoadingNetworkStats, setIsLoadingNetworkStats] = useState(false);

  // State for API-fetched emerging threats
  const [apiEmergingThreats, setApiEmergingThreats] = useState<DashboardEmergingThreat[]>([]);
  const [isLoadingApiEmergingThreats, setIsLoadingApiEmergingThreats] = useState<boolean>(true);
  const [errorApiEmergingThreats, setErrorApiEmergingThreats] = useState<string | null>(null);

  // State for API-fetched threat feeds
  interface ApiFeedStatus {
    id: string;
    name: string;
    status: string;
    entries: number;
    last_updated?: string | null;
    is_subscribed: boolean;
  }
  const [threatFeedsApiData, setThreatFeedsApiData] = useState<ApiFeedStatus[]>([]);
  const [isLoadingThreatFeeds, setIsLoadingThreatFeeds] = useState<boolean>(true);
  const [errorThreatFeeds, setErrorThreatFeeds] = useState<string | null>(null);

  // State for API-fetched user summary
  interface UserSummaryData {
    total_users: number;
    admin_users: number;
    standard_users: number;
  }
  const [userSummaryData, setUserSummaryData] = useState<UserSummaryData | null>(null);
  const [isLoadingUserSummary, setIsLoadingUserSummary] = useState<boolean>(true);
  const [errorUserSummary, setErrorUserSummary] = useState<string | null>(null);

  // State for API-fetched ML accuracy
  interface MlAccuracyData {
    model_name: string;
    accuracy: number;
    last_trained: string; // ISO date string
  }
  const [mlAccuracyData, setMlAccuracyData] = useState<MlAccuracyData | null>(null);
  const [isLoadingMlAccuracy, setIsLoadingMlAccuracy] = useState<boolean>(true);
  const [errorMlAccuracy, setErrorMlAccuracy] = useState<string | null>(null);

  // State for API-fetched users list
  interface UserListData { // Based on UserInDB schema from backend
    id: number;
    username: string;
    email: string;
    full_name?: string | null;
    is_active: boolean;
    is_superuser: boolean;
    created_at: string; // ISO date string
    updated_at?: string | null; // ISO date string
  }
  // const [usersListData, setUsersListData] = useState<UserListData[]>([]); // Handled by UserList.tsx
  // const [isLoadingUsersList, setIsLoadingUsersList] = useState<boolean>(true); // Handled by UserList.tsx
  // const [errorUsersList, setErrorUsersList] = useState<string | null>(null); // Handled by UserList.tsx

  // State for API-fetched general settings
  interface GeneralSettingsData {
    notification_email: string;
    update_frequency: string;
    data_retention_days: number;
  }
  const [generalSettingsData, setGeneralSettingsData] = useState<GeneralSettingsData | null>(null);
  const [isLoadingGeneralSettings, setIsLoadingGeneralSettings] = useState<boolean>(true);
  const [errorGeneralSettings, setErrorGeneralSettings] = useState<string | null>(null);
  
  // Determine active tab based on current route
  const activeTab = routeToTabMap[location.pathname] || 'overview';

  // Daily report summary
  const [dailySummary, setDailySummary] = useState<{
    network24h: { sent_mb: number; recv_mb: number };
    threatSummary: {
      counts: { critical: number; warning: number; info: number };
      details: Record<string, any[]>;
    };
  } | null>(null);


  useEffect(() => {
    if (!offline) {
      const socket = getSocket();
      socket.on('daily_summary', (data) => {
        setDailySummary(data);
      });
  
      // 2. Immediately request it on load
      socket.emit('request_daily_summary');
  
      return () => {
        socket.off('daily_summary');
      };
    }
  }, [offline, getSocket]); // Added getSocket to dependency array

  // Fetch Emerging Threats from API
  useEffect(() => {
    const fetchDashboardEmergingThreats = async () => {
      setIsLoadingApiEmergingThreats(true);
      setErrorApiEmergingThreats(null);
      try {
        const response = await fetch('http://127.0.0.1:8000/api/v1/threat-intelligence/emerging-threats');
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data: BackendEmergingThreat[] = await response.json();
        
        const processedData: DashboardEmergingThreat[] = data.slice(0, 3).map((threat, index) => { // Take top 3 for dashboard display
          let severity: DashboardEmergingThreat["severity"] = "unknown";
          let name = threat.id || threat.indicator || `Threat ${index + 1}`;
          let details = threat.summary || threat.threat_type || 'No specific details.';
          
          if (threat.type === 'CVE') {
            severity = "critical"; // Example severity for CVEs
          } else if (threat.type === 'OSINT Indicator') {
            if (threat.threat_type?.toLowerCase().includes("malware")) severity = "warning";
            else severity = "info";
          }

          return {
            id: threat.id || threat.indicator || `dash-et-${index}`,
            name: name,
            severity: severity,
            type: threat.type,
            details: details,
            affectedSystems: [], // Not available from this specific backend endpoint structure
            timestamp: threat.published ? new Date(threat.published) : (threat.last_seen ? new Date(threat.last_seen) : new Date()),
            // detectionCount: undefined, // Not available
          };
        });
        setApiEmergingThreats(processedData);
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'An unknown error occurred';
        setErrorApiEmergingThreats(msg);
        console.error("Failed to fetch dashboard emerging threats:", e);
      } finally {
        setIsLoadingApiEmergingThreats(false);
      }
    };
    fetchDashboardEmergingThreats();

    const fetchThreatFeeds = async () => {
      setIsLoadingThreatFeeds(true);
      setErrorThreatFeeds(null);
      try {
        const response = await fetch('http://127.0.0.1:8000/api/v1/threat-intelligence/feeds');
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data: ApiFeedStatus[] = await response.json();
        setThreatFeedsApiData(data);
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'An unknown error occurred';
        setErrorThreatFeeds(msg);
        console.error("Failed to fetch threat feeds:", e);
      } finally {
        setIsLoadingThreatFeeds(false);
      }
    };
    fetchThreatFeeds();

    const fetchUserSummary = async () => {
      setIsLoadingUserSummary(true);
      setErrorUserSummary(null);
      try {
        const response = await fetch('http://127.0.0.1:8000/api/v1/users');
        // const response = await fetch('https://ecyber-backend.onrender.com/api/v1/users');
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data: UserSummaryData = await response.json();
        setUserSummaryData(data);
        console.log("Users: ", data)
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'An unknown error occurred';
        setErrorUserSummary(msg);
        console.error("Failed to fetch user summary:", e);
      } finally {
        setIsLoadingUserSummary(false);
      }
    };
    fetchUserSummary();

    const fetchMlAccuracy = async () => {
      setIsLoadingMlAccuracy(true);
      setErrorMlAccuracy(null);
      try {
        const response = await fetch('http://127.0.0.1:8000/api/v1/ml-models/accuracy');
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data: MlAccuracyData = await response.json();
        setMlAccuracyData(data);
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'An unknown error occurred';
        setErrorMlAccuracy(msg);
        console.error("Failed to fetch ML accuracy:", e);
      } finally {
        setIsLoadingMlAccuracy(false);
      }
    };
    fetchMlAccuracy();

    const fetchUsersList = async () => {
      setIsLoadingUsersList(true);
      setErrorUsersList(null);
      try {
        const response = await fetch('http://127.0.0.1:8000/api/v1/users/'); // Assuming this is the correct endpoint from v1 router
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data: UserListData[] = await response.json();
        setUsersListData(data);
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'An unknown error occurred';
        setErrorUsersList(msg);
        console.error("Failed to fetch users list:", e);
      } finally {
        setIsLoadingUsersList(false);
      }
    };
    // fetchUsersList(); // Handled by UserList.tsx

    const fetchGeneralSettings = async () => {
      setIsLoadingGeneralSettings(true);
      setErrorGeneralSettings(null);
      try {
        const response = await fetch('http://127.0.0.1:8000/api/v1/settings/general');
        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }
        const data: GeneralSettingsData = await response.json();
        setGeneralSettingsData(data);
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'An unknown error occurred';
        setErrorGeneralSettings(msg);
        console.error("Failed to fetch general settings:", e);
      } finally {
        setIsLoadingGeneralSettings(false);
      }
    };
    fetchGeneralSettings();
  }, []);
  
  // Handle tab change
  const handleTabChange = (value: string) => {
    // Map tab values back to routes
    const tabToRouteMap: Record<string, string> = {
      'overview': '/dashboard',
      'threat-intel': '/threats',
      'network': '/network',
      'logs': '/logs',
      'models': '/models',
      'users': '/users',
      'settings': '/settings'
    };
    
    if (tabToRouteMap[value]) {
      navigate(tabToRouteMap[value]);
    }
  };
  
  // Calculate Threat Metrics from Redux state
  

  useDeepCompareEffect(() => {
    const safeSecurityAlerts = Array.isArray(securityAlerts) ? securityAlerts : [];
    const safeThreatDetections = Array.isArray(threatDetections) ? threatDetections : [];
    const safeFirewallEvents = Array.isArray(firewallEvents) ? firewallEvents : [];

    const critical =
      safeSecurityAlerts.filter(a => a.severity === "Critical").length +
      safeThreatDetections.filter(td => td.severity === "Critical").length;

    const warning =
      safeSecurityAlerts.filter(a => a.severity === "High" || a.severity === "Medium").length +
      safeThreatDetections.filter(td => td.severity === "High" || td.severity === "Medium").length;

    const info =
      safeSecurityAlerts.filter(a => a.severity === "Low" || a.severity === "Info").length +
      safeThreatDetections.filter(td => td.severity === "Low" || td.severity === "Info").length;

    const blocked = safeFirewallEvents.filter(fe => fe.action === "Blocked").length;

    const newMetrics = { critical, warning, info, blocked };

    setCurrentThreatMetrics(prev => {
      const same =
        prev.critical === newMetrics.critical &&
        prev.warning === newMetrics.warning &&
        prev.info === newMetrics.info &&
        prev.blocked === newMetrics.blocked;

      return same ? prev : newMetrics;
    });

    setLastUpdated(new Date());
  }, [securityAlerts, threatDetections, firewallEvents]);

  
  useEffect(() => {
    const safeSecurityAlerts = Array.isArray(securityAlerts) ? securityAlerts : [];
  
    const hasAnomaly = safeSecurityAlerts.some(
      alert =>
        (alert.severity === "Critical" && alert.threat_type?.toLowerCase().includes("anomaly")) ||
        alert.description?.toLowerCase().includes("unusual pattern")
    );
  
    setIsAnomalyDetected(hasAnomaly);
  
    if (hasAnomaly) {
      const now = Date.now();
      // Throttle toast notifications for anomalies
      if (now - lastAnomalyToastTime > 60000) {
        const anomalyAlert = safeSecurityAlerts.find(
          a => a.severity === "Critical" && a.threat_type?.toLowerCase().includes("anomaly")
        );
  
        toast({
          title: "Network Anomaly Detected",
          description: anomalyAlert?.description || "Unusual activity detected.",
          variant: "destructive"
        });
  
        setLastAnomalyToastTime(now);
      }
    }
  }, [securityAlerts, toast, lastAnomalyToastTime]);

  useEffect(() => {
    if (activeTab === 'network' && !networkStats) { // Fetch only if tab is active and stats are not yet loaded
      const fetchNetworkStats = async () => {
        setIsLoadingNetworkStats(true);
        try {
          // TODO: Add authentication headers if required by the backend
          const response = await fetch('http://127.0.0.1/api/network/stats'); 
          if (!response.ok) {
            throw new Error(`Failed to fetch network stats: ${response.statusText}`);
          }
          const data = await response.json();
          setNetworkStats(data);
          toast({ title: "Network Stats Loaded", description: "Successfully fetched network statistics." });
        } catch (error) {
          console.error("Error fetching network stats:", error);
          toast({ 
            title: "Error Loading Network Stats", 
            description: error instanceof Error ? error.message : "Could not load network stats.",
            variant: "destructive"
          });
        } finally {
          setIsLoadingNetworkStats(false);
        }
      };
      fetchNetworkStats();
    }
  }, [activeTab, networkStats]); // Add networkStats to dependencies to prevent re-fetch if already loaded
  
  
  // Activity Stream Data Mapping
  const mappedActivities = React.useMemo(() => {
    const combinedActivities: ActivityItemProps[] = [];

    securityAlerts && securityAlerts.forEach(alert => {
      let type: ActivityItemProps['type'] = 'system';
      if (alert.threat_type?.toLowerCase().includes('auth') || alert.description?.toLowerCase().includes('login')) type = 'auth';
      else if (alert.protocol || alert.source_ip || alert.destination_ip) type = 'network';
      if (alert.severity === 'Critical' || alert.severity === 'High') type = 'threat';


      let streamSeverity: ActivityItemProps['severity'] = 'info';
      if (alert.severity === 'Critical') streamSeverity = 'critical';
      else if (alert.severity === 'High' || alert.severity === 'Medium') streamSeverity = 'warning';
      // TODO: Add mapping for 'blocked' if applicable from alert data

      combinedActivities.push({
        id: alert.id,
        type: type,
        severity: streamSeverity,
        message: alert.description,
        details: `Threat Type: ${alert.threat_type || 'N/A'}${alert.rule_id ? `, Rule: ${alert.rule_id}` : ''}`,
        source: alert.source_ip,
        destination: alert.destination_ip,
        timestamp: new Date(alert.timestamp),
      });
    });

    httpActivities.forEach(http => {
      let severity: ActivityItemProps['severity'] = 'info';
      if (http.risk_level === 'Critical' || http.risk_level === 'High') severity = 'critical';
      else if (http.risk_level === 'Medium') severity = 'warning';
      
      combinedActivities.push({
        id: http.id,
        type: 'network',
        severity: severity,
        message: `${http.method} ${http.host}${http.path}`,
        details: `Status: ${http.status_code}, User-Agent: ${http.user_agent?.substring(0,50)}...`,
        source: http.source_ip,
        destination: http.destination_ip,
        timestamp: new Date(http.timestamp),
      });
    });
    
    // Add more mappers for dnsActivities, etc. if needed for the stream
    dnsActivities && dnsActivities.forEach(dns => {
      let severity: ActivityItemProps['severity'] = 'info';
      if (dns.is_suspicious || dns.tunnel_detected || (dns.dga_score && dns.dga_score > 0.7)) {
        severity = 'warning';
      }
      if (dns.tunnel_detected && dns.is_suspicious) {
        severity = 'critical';
      }
    
      let message = `DNS Activity: ${dns.source_ip}`;
      if (dns.queries && dns.queries.length > 0) {
        const query = dns.queries[0];
        message = `DNS Query: ${query.query_name} (Type: ${query.query_type}) from ${dns.source_ip}`;
      } else if (dns.responses && dns.responses.length > 0) {
        const response = dns.responses[0];
        message = `DNS Response: ${response.name} (Type: ${response.type}) from ${dns.source_ip}`;
      }
      
      combinedActivities.push({
        id: dns.id || `dns-${new Date(dns.timestamp).getTime()}-${dns.source_ip}`,
        type: 'network',
        severity: severity,
        message: message,
        details: `DGA Score: ${dns.dga_score?.toFixed(2)}, NXDomain Ratio: ${dns.nxdomain_ratio?.toFixed(2)}. ${dns.tunnel_detected ? 'Tunnel Detected.' : ''} ${dns.is_suspicious ? 'Suspicious.' : ''}`,
        source: dns.source_ip,
        destination: dns.responses && dns.responses.length > 0 ? dns.responses.map(r => r.response_data).join(', ') : undefined,
        timestamp: new Date(dns.timestamp),
      });
    });

    firewallEvents && firewallEvents.forEach(fe => {
      let severity: ActivityItemProps['severity'] = 'info';
      if (fe.action?.toLowerCase() === 'blocked' || fe.action?.toLowerCase() === 'denied') {
        severity = 'critical';
      } else if (fe.severity?.toLowerCase() === 'high' || fe.severity?.toLowerCase() === 'medium') {
        severity = 'warning';
      }

      combinedActivities.push({
        id: fe.id || `fw-${new Date(fe.timestamp).getTime()}-${fe.source_ip}`,
        type: 'network', // Could be 'system' depending on context
        severity: severity,
        message: `Firewall: ${fe.action} ${fe.protocol} from ${fe.source_ip}:${fe.source_port} to ${fe.destination_ip}:${fe.destination_port}`,
        details: `Rule: ${fe.rule_id || 'N/A'}. Reason: ${fe.reason || 'N/A'}. Severity: ${fe.severity || 'N/A'}`,
        source: fe.source_ip,
        destination: fe.destination_ip,
        timestamp: new Date(fe.timestamp),
      });
    });

    tcpActivities && tcpActivities.forEach(tcp => {
      let severity: ActivityItemProps['severity'] = 'info';
      if (tcp.flags?.RST) severity = 'warning';
      if (tcp.syn_flood_detected || tcp.rst_attack_detected) severity = 'critical';
      else if (tcp.fin_scan_detected || tcp.sequence_analysis?.predictable) severity = 'warning';

      combinedActivities.push({
        id: tcp.id || `tcp-${new Date(tcp.timestamp).getTime()}-${tcp.source_ip}-${tcp.source_port}`,
        type: 'network',
        severity: severity,
        message: `TCP: ${tcp.source_ip}:${tcp.source_port} -> ${tcp.destination_ip}:${tcp.destination_port} Flags: ${Object.entries(tcp.flags || {}).filter(([, val]) => val).map(([key]) => key).join(',') || 'N/A'}`,
        details: `Window: ${tcp.window_size}, Seq: ${tcp.seq_num}, Payload: ${tcp.tcp_payload_size}B. ${tcp.sequence_analysis?.predictable ? 'Predictable Seq!' : ''} ${tcp.syn_flood_detected ? 'SYN Flood!' : ''}`,
        source: tcp.source_ip,
        destination: tcp.destination_ip,
        timestamp: new Date(tcp.timestamp),
      });
    });

    udpActivities && udpActivities.forEach(udp => {
      let severity: ActivityItemProps['severity'] = 'info';
      if (udp.udp_flood_detected || udp.ntp_amplification_detected) severity = 'critical';
      else if (udp.suspicious_port_detected) severity = 'warning';
      
      combinedActivities.push({
        id: udp.id || `udp-${new Date(udp.timestamp).getTime()}-${udp.source_ip}-${udp.source_port}`,
        type: 'network',
        severity: severity,
        message: `UDP: ${udp.source_ip}:${udp.source_port} -> ${udp.destination_ip}:${udp.destination_port}`,
        details: `Length: ${udp.length}, Payload: ${udp.udp_payload_size}B. ${udp.ntp_amplification_detected ? 'NTP Amp!' : ''} ${udp.udp_flood_detected ? 'UDP Flood!' : ''}`,
        source: udp.source_ip,
        destination: udp.destination_ip,
        timestamp: new Date(udp.timestamp),
      });
    });

    icmpActivities && icmpActivities.forEach(icmp => {
      let severity: ActivityItemProps['severity'] = 'info';
      if (icmp.ping_flood_detected || icmp.ping_of_death_detected) severity = 'warning';
      if (icmp.icmp_redirect_detected) severity = 'critical';

      combinedActivities.push({
        id: icmp.id || `icmp-${new Date(icmp.timestamp).getTime()}-${icmp.source_ip}-${icmp.destination_ip}`,
        type: 'network',
        severity: severity,
        message: `ICMP: ${icmp.source_ip} -> ${icmp.destination_ip} Type: ${icmp.icmp_type}, Code: ${icmp.icmp_code}`,
        details: `Payload: ${icmp.icmp_payload_size}B. ${icmp.ping_of_death_detected ? 'Ping of Death!' : ''} ${icmp.ping_flood_detected ? 'Ping Flood!' : ''}`,
        source: icmp.source_ip,
        destination: icmp.destination_ip,
        timestamp: new Date(icmp.timestamp),
      });
    });

    arpActivities && arpActivities.forEach(arp => {
      let severity: ActivityItemProps['severity'] = 'info';
      if (arp.arp_spoofing_detected || arp.mac_spoofing_detected) severity = 'critical'; // ARP spoofing is serious
      else if (arp.gratuitous_arp_detected) severity = 'warning';

      combinedActivities.push({
        id: arp.id || `arp-${new Date(arp.timestamp).getTime()}-${arp.sender_ip}`,
        type: 'network',
        severity: severity,
        message: `ARP: ${arp.operation} - Sender: ${arp.sender_ip} (${arp.sender_mac}), Target: ${arp.target_ip} (${arp.target_mac || 'N/A'})`,
        details: `${arp.arp_spoofing_detected ? 'ARP Spoofing!' : ''} ${arp.mac_spoofing_detected ? 'MAC Spoofing!' : ''} ${arp.gratuitous_arp_detected ? 'Gratuitous ARP.' : ''}`,
        source: arp.sender_ip,
        destination: arp.target_ip, // Or N/A if not applicable for requests
        timestamp: new Date(arp.timestamp),
      });
    });

    payloadAnalysisEvents && payloadAnalysisEvents.forEach(pa => {
      let severity: ActivityItemProps['severity'] = 'info';
      if (pa.shellcode_detected || pa.sql_injection_detected || pa.xss_detected) severity = 'critical';
      else if (pa.exploit_kit_pattern_detected || pa.obfuscation_detected || pa.high_entropy_detected) severity = 'warning';

      combinedActivities.push({
        id: pa.id || `payload-${new Date(pa.timestamp).getTime()}-${pa.source_ip}`,
        type: 'threat',
        severity: severity,
        message: `Payload Anomaly: ${pa.protocol} from ${pa.source_ip || 'N/A'} to ${pa.destination_ip || 'N/A'}`,
        details: `Size: ${pa.actual_payload_size}, Entropy: ${pa.entropy?.toFixed(2)}. ${pa.shellcode_detected ? 'Shellcode!' : ''} ${pa.sql_injection_detected ? 'SQLi!' : ''} ${pa.xss_detected ? 'XSS!' : ''}`,
        source: pa.source_ip,
        destination: pa.destination_ip,
        timestamp: new Date(pa.timestamp),
      });
    });

    behaviorAnalysisEvents && behaviorAnalysisEvents.forEach(ba => {
      let severity: ActivityItemProps['severity'] = 'info';
      // Determine behavior_type for message (example, could be an actual field)
      let behavior_type = 'General';
      if (ba.port_scan_detected) { behavior_type = 'Port Scan'; severity = 'warning'; }
      if (ba.dos_attempt_detected) { behavior_type = 'DoS Attempt'; severity = 'critical'; }
      if (ba.data_exfiltration_detected) { behavior_type = 'Data Exfiltration'; severity = 'critical'; }

      combinedActivities.push({
        id: ba.id || `behavior-${new Date(ba.timestamp).getTime()}-${ba.source_ip}`,
        type: 'threat', 
        severity: severity,
        message: `Behavior Anomaly: ${ba.source_ip} - ${behavior_type}`,
        details: `Flow ID: ${ba.flow_id}, Duration: ${ba.duration_seconds?.toFixed(2)}s. Packets: ${ba.packet_count_in_flow}, Bytes: ${ba.byte_count_in_flow}. ${ba.port_scan_detected ? 'Port Scan!' : ''} ${ba.dos_attempt_detected ? 'DoS Attempt!' : ''} ${ba.data_exfiltration_detected ? 'Data Exfil!' : ''}`,
        source: ba.source_ip,
        destination: ba.destination_ip, // May not always be relevant for behavior analysis
        timestamp: new Date(ba.timestamp),
      });
    });

    return combinedActivities.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime()).slice(0, 50);
  }, [
    securityAlerts, 
    httpActivities, 
    dnsActivities, 
    firewallEvents, 
    tcpActivities, 
    udpActivities, 
    icmpActivities, 
    arpActivities, 
    payloadAnalysisEvents, 
    behaviorAnalysisEvents
  ]);

  // REMOVED: Emerging Threats derived from Redux, will now use apiEmergingThreats
  // const emergingThreats = React.useMemo(() => { ... }, [threatDetections, securityAlerts]);


  function formatBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KB', 'MB', 'GB', 'TB'];
    let i = -1;
    do {
      bytes = bytes / 1024;
      i++;
    } while (bytes >= 1024 && i < units.length - 1);
    return `${bytes.toFixed(2)} ${units[i]}`;
  }
  

  
  return (
    <div className="flex h-screen bg-background">
      
      <div className="flex-1 flex flex-col overflow-hidden">
        
        <main className="flex-1 overflow-auto p-6">
          <div className="max-w-7xl mx-auto">
            {/* Dashboard header with anomaly indicator */}
            <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-2xl font-bold tracking-tight">
                    {location.pathname === '/dashboard' ? 'Security Dashboard' : 
                     location.pathname === '/threats' ? 'Threat Intelligence' :
                     location.pathname === '/network' ? 'Network Map' :
                     location.pathname === '/logs' ? 'Logs & Analysis' :
                     location.pathname === '/models' ? 'ML & AI Models' :
                     location.pathname === '/users' ? 'Access Control' :
                     location.pathname === '/settings' ? 'System Settings' : 'Security Dashboard'}
                  </h1>
                  {isAnomalyDetected && (
                    <Badge variant="outline" className="bg-red-500/10 border-red-500 text-red-400 animate-pulse">
                      <AlertOctagon className="mr-1 h-3 w-3" /> Anomaly Detected
                    </Badge>
                  )}
                </div>
                <p className="text-muted-foreground">
                  {location.pathname === '/dashboard' ? 'Monitor and analyze your security posture in real-time' :
                   location.pathname === '/threats' ? 'Track and respond to emerging security threats' :
                   location.pathname === '/network' ? 'Visualize and monitor network traffic' : 
                   location.pathname === '/logs' ? 'Search and analyze security event logs' :
                   location.pathname === '/models' ? 'Manage and train AI security models' :
                   location.pathname === '/users' ? 'Manage user access and permissions' :
                   location.pathname === '/settings' ? 'Configure system settings and integrations' :
                   'Monitor and analyze your security posture in real-time'}
                </p>
              </div>
              
              <div className="mt-4 md:mt-0 text-xs text-muted-foreground flex items-center">
                <Bell className="mr-1 h-3 w-3" />
                Last updated: {lastUpdated.toLocaleTimeString()}
              </div>
            </div>
            
            {/* Metrics cards */}
            {location.pathname === '/dashboard' && (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <MetricsCard 
                  title="Traffic Volume" 
                  value={ formatBytes(networkVolume)}
                  description="Total network traffic in last 24h"
                  icon={<Activity size={16} />}
                  // Trend data would need historical daily summaries
                  // trend={{ direction: 'up', value: '12%', label: 'vs yesterday' }} 
                  variant="info"
                />
                
                <MetricsCard 
                  title="Threats Today" 
                  value={currentThreatMetrics.critical + currentThreatMetrics.warning + currentThreatMetrics.info + currentThreatMetrics.blocked}
                  description={`${currentThreatMetrics.critical} critical, ${currentThreatMetrics.warning} warning, ${currentThreatMetrics.blocked} blocked`}
                  icon={<Shield size={16} />}
                  // Trend data would need historical metrics
                  // trend={{ direction: 'down', value: '5%', label: 'vs yesterday' }}
                  variant={currentThreatMetrics.critical > 0 ? "destructive" : currentThreatMetrics.warning > 0 ? "warning" : "info"}
                />
                
                <MetricsCard 
                  title="Active Users"
                  value={isLoadingUserSummary ? "Loading..." : (userSummaryData ? String(userSummaryData?.length) : "N/A")}
                  description={
                    isLoadingUserSummary ? "" : 
                    errorUserSummary ? `Error: ${errorUserSummary.substring(0,20)}...` :
                    (userSummaryData ? `0 admins, ${userSummaryData?.length} standard` : "No data")
                  }
                  icon={<Users size={16} />}
                  // trend={{ direction: 'neutral', value: '0%', label: 'unchanged' }} // Trend data not available
                  variant={errorUserSummary ? "destructive" : "info"}
                />
                
                <MetricsCard 
                  title="ML Accuracy"
                  value={isLoadingMlAccuracy ? "Loading..." : (mlAccuracyData ? `${(mlAccuracyData.accuracy * 100).toFixed(1)}%` : "N/A")}
                  description={
                    isLoadingMlAccuracy ? `Fetching ${mlAccuracyData?.model_name || 'model'} data...` :
                    errorMlAccuracy ? `Error: ${errorMlAccuracy.substring(0,20)}...` :
                    (mlAccuracyData ? `${mlAccuracyData.model_name} (Trained: ${new Date(mlAccuracyData.last_trained).toLocaleDateString()})` : "No data")
                  }
                  icon={<Database size={16} />}
                  // trend={{ direction: 'up', value: '0.2%', label: 'since last training' }} // Trend data not available
                  variant={errorMlAccuracy ? "destructive" : (mlAccuracyData && mlAccuracyData.accuracy > 0.9 ? "success" : "info")}
                />
              </div>
            )}
            
            {/* Emerging threats section */}
            {(location.pathname === '/dashboard' || location.pathname === '/threats') && (
              <Card className="mb-6 border-red-500/20 shadow-lg animate-fade-in">
                <CardHeader className="pb-2">
                  <CardTitle className="text-lg font-medium flex items-center">
                    <AlertOctagon className="mr-2 text-red-400" size={18} />
                    Emerging Threats
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {isLoadingApiEmergingThreats && <p className="text-sm text-muted-foreground">Loading threats...</p>}
                  {errorApiEmergingThreats && <p className="text-sm text-red-500">Error: {errorApiEmergingThreats}</p>}
                  {!isLoadingApiEmergingThreats && !errorApiEmergingThreats && apiEmergingThreats.length > 0 ? (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      {apiEmergingThreats.map((threat) => (
                        <div 
                          key={threat.id}
                          className={cn(
                            "glass-card p-4 border rounded-lg",
                            threat.severity === 'critical' ? "border-red-500/20" : 
                            (threat.severity === 'warning' ? "border-amber-500/20" : "border-sky-500/20")
                          )}
                        >
                          <div className="flex justify-between items-start mb-2">
                            <h3 className="font-medium text-sm">{threat.name}</h3>
                            <Badge 
                              variant="outline"
                              className={cn(
                                "text-xs",
                                threat.severity === 'critical' ? "border-red-500 text-red-400" : 
                                (threat.severity === 'warning' ? "border-amber-500 text-amber-400" : "border-sky-500 text-sky-400")
                              )}
                            >
                              {threat.severity.toUpperCase()}
                            </Badge>
                          </div>
                          <p className="text-xs text-muted-foreground mb-2">{threat.type}</p>
                          <p className="text-xs mb-3 h-10 overflow-y-auto">{threat.details}</p>
                          {/* Affected Systems might be empty as it's not in backend data */}
                          {threat.affectedSystems && threat.affectedSystems.length > 0 && (
                            <div className="text-xs text-muted-foreground">
                              <span>Affected: </span>
                              {threat.affectedSystems.map((sys, i) => (
                                <Badge key={i} variant="secondary" className="mr-1 text-[10px]">
                                  {sys}
                                </Badge>
                              ))}
                            </div>
                          )}
                           <div className="text-xs text-muted-foreground mt-1">
                                Timestamp: {new Date(threat.timestamp).toLocaleDateString()} {new Date(threat.timestamp).toLocaleTimeString()}
                           </div>
                          <div className="flex items-center justify-between mt-3 pt-2 border-t border-border/50">
                            <span className="text-xs text-muted-foreground">
                              {/* Detection count not available from this API */}
                            </span>
                            <Button variant="ghost" size="sm" className="h-6 text-xs">
                              Investigate <ArrowRight className="ml-1" size={12} />
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    !isLoadingApiEmergingThreats && !errorApiEmergingThreats && <p className="text-sm text-muted-foreground">No critical or high severity emerging threats reported by API.</p>
                  )}
                </CardContent>
              </Card>
            )}
            
            {/* Main content - tabs */}
            <Tabs value={activeTab} onValueChange={handleTabChange} className="space-y-4">
              <TabsList>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="threat-intel">Threat Intelligence</TabsTrigger>
                <TabsTrigger value="network">Network</TabsTrigger>
                <TabsTrigger value="logs">Logs</TabsTrigger>
                <TabsTrigger value="http-log">HTTP Log</TabsTrigger>
                <TabsTrigger value="dns-log">DNS Log</TabsTrigger>
                {location.pathname === '/models' && <TabsTrigger value="models">ML Models</TabsTrigger>}
                {location.pathname === '/users' && <TabsTrigger value="users">Users</TabsTrigger>}
                {location.pathname === '/settings' && <TabsTrigger value="settings">Settings</TabsTrigger>}
              </TabsList>
              
              <TabsContent value="overview" className="space-y-4">
                <ThreatMap 
                  className="animate-fade-in" 
                  threatsData={
                    [
                      ...(Array.isArray(securityAlerts) ? securityAlerts : []), 
                      ...(Array.isArray(threatDetections) ? threatDetections : [])
                    ]
                  } 
                />

                {/* Inserted AnomalyInsightsSection here */}
                {/* <AnomalyInsightsSection /> */}
                
                <div className="mt-6">
                  <h2 className="text-xl font-semibold mb-4 flex items-center">
                    Recent Activity
                    <Badge className="ml-2 bg-blue-500/20 border-blue-400 text-blue-400">
                      Live
                    </Badge>
                    <Button variant="ghost" size="sm" className="ml-auto h-7 text-xs">
                      View All <ArrowRight className="ml-1" size={12} />
                    </Button>
                  </h2>
                  <ActivityStream activities={mappedActivities} />
                </div>
              </TabsContent>
              
              <TabsContent value="threat-intel">
                <div className="glass-card p-6">
                  <h2 className="text-xl font-semibold mb-4">Threat Intelligence</h2>
                  <p className="mb-4">View and analyze security threats affecting your organization.</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">Threat Feed Status</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-2">
                        {isLoadingThreatFeeds && <p className="text-sm text-muted-foreground">Loading feed statuses...</p>}
                        {errorThreatFeeds && <p className="text-sm text-red-500">Error: {errorThreatFeeds}</p>}
                        {!isLoadingThreatFeeds && !errorThreatFeeds && threatFeedsApiData.length > 0 ? (
                          threatFeedsApiData.map(feed => (
                            <div key={feed.id} className="flex justify-between items-center">
                              <span>{feed.name} ({feed.entries} entries)</span>
                              <Badge 
                                variant="outline" 
                                className={cn(
                                  feed.status === 'active' && feed.is_subscribed ? "bg-green-500/10 text-green-500" :
                                  !feed.is_subscribed ? "bg-gray-500/10 text-gray-500" :
                                  "bg-amber-500/10 text-amber-500" // Error or pending
                                )}
                              >
                                {feed.is_subscribed ? (feed.status === 'active' ? 'Active' : (feed.status === 'error' ? 'Error' : 'Pending')) : 'Unsubscribed'}
                              </Badge>
                            </div>
                          ))
                        ) : (
                          !isLoadingThreatFeeds && !errorThreatFeeds && <p className="text-sm text-muted-foreground">No threat feed statuses available.</p>
                        )}
                      </CardContent>
                    </Card>
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">Latest IOCs</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {isLoadingApiEmergingThreats && <p className="text-sm text-muted-foreground">Loading IOCs...</p>}
                        {!isLoadingApiEmergingThreats && apiEmergingThreats.length > 0 ? (
                          <div className="space-y-2 text-sm">
                            {apiEmergingThreats
                              .filter(threat => threat.type === 'OSINT Indicator' && threat.id) // Assuming 'id' holds the indicator value for OSINT
                              .slice(0, 2) // Take first 2 OSINT indicators
                              .map(ioc => (
                                <div key={ioc.id} className="p-2 bg-background rounded-md">
                                  <div className="font-mono text-xs">{ioc.id}</div>
                                  <div className="text-xs text-muted-foreground">{ioc.name} - {ioc.details}</div>
                                </div>
                            ))}
                            {apiEmergingThreats.filter(threat => threat.type === 'OSINT Indicator' && threat.id).length === 0 && (
                              <p className="text-xs text-muted-foreground">No OSINT indicators found in recent emerging threats.</p>
                            )}
                          </div>
                        ) : (
                          !isLoadingApiEmergingThreats && <p className="text-xs text-muted-foreground">No emerging threats data to derive IOCs from.</p>
                        )}
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="network">
                <div className="glass-card p-6">
                  <h2 className="text-xl font-semibold mb-4">Network Statistics</h2>
                  <p className="mb-4 text-muted-foreground">Overview of network traffic and sniffer performance.</p>
                  {isLoadingNetworkStats && <p>Loading network data...</p>}
                  {!isLoadingNetworkStats && !networkStats && <p>No network data available or failed to load.</p>}
                  {networkStats && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-base">Sniffer Performance</CardTitle>
                        </CardHeader>
                        <CardContent className="text-sm space-y-2">
                          <p><strong>Total Packets Processed:</strong> {networkStats.total_packets?.toLocaleString() || 'N/A'}</p>
                          <p><strong>Total Bytes Sniffed:</strong> {(networkStats.total_bytes_processed / (1024*1024))?.toFixed(2) || 'N/A'} MB</p>
                          <p><strong>Sniffer Uptime:</strong> {networkStats.uptime_seconds?.toFixed(0) || 'N/A'} seconds</p>
                           <p><strong>Avg. Packets/Sec:</strong> {networkStats.avg_packets_per_second?.toFixed(2) || 'N/A'}</p>
                        </CardContent>
                      </Card>
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-base">Protocol Distribution</CardTitle>
                        </CardHeader>
                        <CardContent>
                          {networkStats.protocols && Object.keys(networkStats.protocols).length > 0 ? (
                            <ul className="list-disc pl-5 text-sm space-y-1">
                              {Object.entries(networkStats.protocols).map(([protocol, count]) => (
                                <li key={protocol}>
                                  <span className="font-medium">{protocol}:</span> {Number(count).toLocaleString()} packets
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="text-sm text-muted-foreground">No protocol data available.</p>
                          )}
                        </CardContent>
                      </Card>
                      <Card className="md:col-span-2">
                        <CardHeader>
                          <CardTitle className="text-base">Top Talkers (Source IPs)</CardTitle>
                        </CardHeader>
                        <CardContent>
                          {networkStats.top_talkers && Object.keys(networkStats.top_talkers).length > 0 ? (
                             <div className="overflow-x-auto">
                              <table className="w-full text-sm">
                                <thead>
                                  <tr className="text-left text-muted-foreground">
                                    <th className="py-2 pr-2 font-normal">IP Address</th>
                                    <th className="py-2 pl-2 font-normal">Packets Sent</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {Object.entries(networkStats.top_talkers)
                                    .sort(([, a], [, b]) => Number(b) - Number(a)) // Sort by packet count desc
                                    .slice(0, 10) // Display top 10
                                    .map(([ip, count]) => (
                                    <tr key={ip} className="border-t border-border">
                                      <td className="py-2 pr-2 font-mono">{ip}</td>
                                      <td className="py-2 pl-2">{Number(count).toLocaleString()}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          ) : (
                            <p className="text-sm text-muted-foreground">No top talker data available.</p>
                          )}
                        </CardContent>
                      </Card>
                    </div>
                  )}
                </div>
              </TabsContent>
              
              <TabsContent value="logs">
                <div className="glass-card p-6">
                  <h2 className="text-xl font-semibold mb-4">Aggregated Security Logs</h2>
                  <p className="mb-4 text-muted-foreground">Chronological stream of all monitored activities and alerts.</p>
                  <ActivityStream activities={mappedActivities} maxItems={100} />
                </div>
              </TabsContent>
              
              <TabsContent value="models">
                <div className="glass-card p-6">
                  <h2 className="text-xl font-semibold mb-4">ML & AI Models</h2>
                  <p className="mb-4">View and manage machine learning models for security analysis.</p>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <Card>
                      <CardHeader>
                        <CardTitle className="text-base">Anomaly Detection</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <Badge className="mb-2" variant="outline">Active</Badge>
                        <p className="text-sm text-muted-foreground">Detects unusual patterns in network traffic</p>
                        <div className="mt-4">
                          <div className="text-xs">Accuracy</div>
                          <div className="w-full bg-muted h-2 mt-1 rounded-full">
                            <div className="bg-green-500 h-full rounded-full" style={{ width: "94%" }}></div>
                          </div>
                          <div className="text-xs text-right">94%</div>
                        </div>
                      </CardContent>
                    </Card>
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="users">
                <div className="glass-card p-6">
                  <h2 className="text-xl font-semibold mb-4">Access Control</h2>
                  <p className="mb-4">Manage users and permissions for system access.</p>
                  {/* Replace existing user display logic with UserList component */}
                  <UserList />
                </div>
              </TabsContent>

              <TabsContent value="http-log">
                <div className="glass-card p-6">
                  {/* Title could be part of HttpActivityView or added here if needed */}
                  {/* <h2 className="text-xl font-semibold mb-4">HTTP Activity Log</h2> */}
                  <HttpActivityView activities={httpActivities} />
                </div>
              </TabsContent>

              <TabsContent value="dns-log">
                <div className="glass-card p-6">
                  {/* <h2 className="text-xl font-semibold mb-4">DNS Activity Log</h2> */}
                  <DnsActivityView activities={dnsActivities} />
                </div>
              </TabsContent>
              
              <TabsContent value="settings">
                <div className="glass-card p-6">
                  <h2 className="text-xl font-semibold mb-4">System Settings</h2>
                  <p className="mb-4">Configure system settings and preferences.</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                    <div>
                      <h3 className="text-base font-medium mb-2">Notifications</h3>
                      <Card>
                        <CardContent className="pt-6 space-y-4">
                          {isLoadingGeneralSettings && <p className="text-sm text-muted-foreground">Loading notification settings...</p>}
                          {errorGeneralSettings && <p className="text-sm text-red-500">Error: {errorGeneralSettings}</p>}
                          {generalSettingsData && !isLoadingGeneralSettings && !errorGeneralSettings && (
                            <>
                              <div className="flex items-center justify-between">
                                <div>
                                  <div className="font-medium">Email Alerts</div>
                                  <div className="text-xs text-muted-foreground">
                                    Critical alerts sent to: {generalSettingsData.notification_email}
                                  </div>
                                </div>
                                <Button variant="outline" size="sm" disabled>Configure</Button> 
                              </div>
                              <div className="flex items-center justify-between">
                                <div>
                                  <div className="font-medium">Mobile Notifications</div>
                                  <div className="text-xs text-muted-foreground">Push notifications (config TBD)</div>
                                </div>
                                <Button variant="outline" size="sm" disabled>Configure</Button>
                              </div>
                            </>
                          )}
                        </CardContent>
                      </Card>
                    </div>
                    <div>
                      <h3 className="text-base font-medium mb-2">System</h3>
                      <Card>
                        <CardContent className="pt-6 space-y-4">
                          {isLoadingGeneralSettings && <p className="text-sm text-muted-foreground">Loading system settings...</p>}
                          {errorGeneralSettings && <p className="text-sm text-red-500">Error: {errorGeneralSettings}</p>}
                          {generalSettingsData && !isLoadingGeneralSettings && !errorGeneralSettings && (
                            <>
                              <div className="flex items-center justify-between">
                                <div>
                                  <div className="font-medium">Update Frequency</div>
                                  <div className="text-xs text-muted-foreground">
                                    Check for updates: {generalSettingsData.update_frequency}
                                  </div>
                                </div>
                                <Button variant="outline" size="sm" disabled>Configure</Button>
                              </div>
                              <div className="flex items-center justify-between">
                                <div>
                                  <div className="font-medium">Data Retention</div>
                                  <div className="text-xs text-muted-foreground">
                                    Logs retained for: {generalSettingsData.data_retention_days} days
                                  </div>
                                </div>
                                <Button variant="outline" size="sm" disabled>Configure</Button>
                              </div>
                            </>
                          )}
                        </CardContent>
                      </Card>
                    </div>
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          </div>
        </main>
      </div>
      
      <AIAssistant />
    </div>
  );
};

export default Dashboard;