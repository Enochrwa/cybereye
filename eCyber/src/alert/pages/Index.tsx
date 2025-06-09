
import React, { useEffect, useState, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui/tabs";
import ThreatLevelIndicator from "../components/ThreatLevelIndicator";
import ThreatsCountCard from "../components/ThreatsCountCard";
import SystemHealthCard from "../components/SystemHealthCard";

import RecentAlertsCard from "../components/RecentAlertsCard";
import ThreatDetectionsTable from "../components/ThreatDetectionsTable";
import PhishingDetectionsTable from "../components/PhishingDetectionsTable";
import FirewallEventsTable from "../components/FirewallEventsTable";
import HttpActivityTable from "../components/HttpActivityTable";
import DnsActivityTable from "../components/DnsActivityTable";
import PacketAnalysisTable from "../components/PacketAnalysisTable";
import IPv6ActivityTable from "../components/IPv6ActivityTable";
import ThreatResponseTable from "../components/ThreatResponseTable";
import QuarantinedFilesTable from "../components/QuarantinedFilesTable";
import SecurityHistoryTimeline from "../components/SecurityHistoryTimeline";
import EventHeatMap from "../components/EventHeatMap";
import { Shield, Download, RefreshCcw, AlertCircle, ChevronUp, ChevronDown } from "lucide-react";
import { Button } from "../components/ui/button";
import { useToast } from "../hooks/use-toast";
import { Separator } from "../components/ui/separator";

import { useAlerts } from "../mockData";
import { RootState } from "@/app/store";
import { useSelector } from "react-redux";

import { HttpActivity } from "../types";

const Index = () => {

  // B2: Replace Mock Data with Redux State
  const threatDetections = useSelector((state: RootState) => state.threatDetections.threatDetectionsData);
  const phishingDetections = useSelector((state: RootState) => state.phishingDetections.phishingDetectionsData);
  const firewallEvents = useSelector((state: RootState) => state.firewallEvents.firewallEventsData);
  const dnsActivities = useSelector((state: RootState) => state.dnsActivity.dnsActivities);
  const packetAnalyses = useSelector((state: RootState) => state.packetData.packetEntries);
  const ipv6Activities = useSelector((state: RootState) => state.ipv6Activity.ipv6ActivitiesData);
  const threatResponses = useSelector((state: RootState) => state.threatResponses.threatResponsesData);
  const quarantinedFiles = useSelector((state: RootState) => state.quarantinedFiles.quarantinedFilesData);
  const recentCriticalAlerts = useSelector((state: RootState) => state.securityAlerts.recentAlerts);
  
  const httpActivities = useSelector((state: RootState) => state.socket.httpActivities); // Already using Redux

  // Data for cards that will be fully implemented in Step 4 - using mock for now or parts of it
  // Data for cards that will be fully implemented in Step 4 - using mock for now or parts of it
  // const {
  //   threatLevelData, // To be replaced 
  //   activeThreatCounts, // To be replaced
  // } = useAlerts(); // Removing useAlerts() for these

  // --- Task 3a: ThreatLevelIndicator ---
  // Assuming Alert type has a 'severity' field as per task description.
  // If Alert type from Redux (state.securityAlerts.recentAlerts) doesn't have severity, this will need adjustment or backend change.
  // For now, we'll try to use `threatDetections` as it's more likely to have severity.
  // If `recentCriticalAlerts` is preferred, ensure `Alert` type in its slice includes severity.
  const allAlertsForLevel = useSelector((state: RootState) => state.threatDetections.threatDetectionsData); // Using threatDetections for severity

  const currentThreatLevelData = useMemo(() => {
    if (!allAlertsForLevel || allAlertsForLevel.length === 0) {
      return { level: "Low" as "Critical" | "High" | "Medium" | "Low", description: "No threats detected." };
    }
    // Assuming Alert has a 'severity' field.
    // Type definition for Alert in usePacketSnifferSocket might need update if severity is not optional.
    type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
    const severityOrder: Record<Severity, number> = { "Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5 };
    
    let highestSeverity: Severity = "Info";
    let highestAlertMessage = "System nominal. Current threat level is low.";

    allAlertsForLevel.forEach(alert => {
      const alertSeverity = (alert as any).severity as Severity || "Info"; // Cast if severity is not strictly typed on Alert
      if (severityOrder[alertSeverity] < severityOrder[highestSeverity]) {
        highestSeverity = alertSeverity;
        highestAlertMessage = alert.message;
      }
    });
    
    // Ensure the level matches the component's expected prop type
    const finalLevel = (highestSeverity === "Info" ? "Low" : highestSeverity) as "Critical" | "High" | "Medium" | "Low";

    return {
      level: finalLevel,
      description: `Highest recent alert: ${highestAlertMessage}`
    };
  }, [allAlertsForLevel]);
  
  const currentThreatLevel = currentThreatLevelData.level; // Used by ThreatLevelIndicator component

  // --- Task 3b: ThreatsCountCard ---
  // Using threatDetections from Redux state
  const activeThreatCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    (threatDetections || []).forEach(alert => {
      const severity = ((alert as any).severity || "info").toLowerCase() as keyof typeof counts; // Cast if severity is not on Alert type
      if (counts[severity] !== undefined) {
        counts[severity]++;
      } else if (severity === "critical" || severity === "high" || severity === "medium" || severity === "low") {
        counts[severity]++; // Fallback for case variations if any
      } else {
        counts.info++; // Default to info if severity is unknown
      }
    });
    return counts;
  }, [threatDetections]);

  // --- Task 3c: SystemHealthCard ---
  const systemStats = useSelector((state: RootState) => state.systemMetrics.systemStats);
  const systemStatus = useSelector((state: RootState) => state.systemMetrics.systemStatus);
  
  const systemStatusData = useMemo(() => {
    const healthData: { name: string; status: 'Operational' | 'Degraded' | 'Offline'; description?: string }[] = [];

    // Overall System Health
    let overallStatus: 'Operational' | 'Degraded' | 'Offline' = 'Offline';
    if (systemStatus?.online) {
      overallStatus = 'Operational';
      if (systemStats && (systemStats.cpu > 80 || systemStats.memory > 80)) { // Example: Degraded if CPU/Mem > 80%
        overallStatus = 'Degraded';
      }
    }
    healthData.push({
      name: "Overall System",
      status: overallStatus,
      description: `CPU: ${systemStats?.cpu?.toFixed(1) ?? 'N/A'}% | Memory: ${systemStats?.memory?.toFixed(1) ?? 'N/A'}% | Network: ${systemStats?.network?.toFixed(1) ?? 'N/A'} kB/s`
    });

    // Individual Services
    (systemStatus?.services || []).forEach(serviceName => {
      // Assuming services listed are online and operational unless other data suggests otherwise
      // This part could be more sophisticated if individual service health data becomes available
      healthData.push({
        name: serviceName,
        status: systemStatus?.online ? 'Operational' : 'Offline', // Simplified: if system is online, service is.
        description: "Running smoothly"
      });
    });
     if (!systemStatus?.services?.length && systemStatus?.online) {
        healthData.push({
            name: "Core Services",
            status: "Operational",
            description: "All core services operational."
        });
    }


    return healthData;
  }, [systemStats, systemStatus]);


  // const cached = localStorage.getItem('httpActivity');
  // const initialHttpActivity: HttpActivity[] | null = cached
  //   ? JSON.parse(cached)
  //   : null;
    
  
  // const [httpActivity, setHttpActivity] = useState<HttpActivity[] | null>(initialHttpActivity);
  const [activeTab, setActiveTab] = useState("threats");
  const [networkActiveTab, setNetworkActiveTab] = useState("http");
  const [automatedResponsesActiveTab, setAutomatedResponsesActiveTab] = useState("responses");
  const [sectionsExpanded, setSectionsExpanded] = useState({
    threatIntelligence: true,
    networkActivity: true,
    automatedResponses: true,
    history: true
  });

  // const socket = useSocket('http://127.0.0.1:8000/packet_sniffer', 'socket.io', {});

  // useSocket('http://127.0.0.1:8000/packet_sniffer', 'socket.io', {})

  const { toast } = useToast();


  
  

  // --- Task 3d: allTimelineEvents Timestamp Handling ---
  const allTimelineEvents = useMemo(() => {
    const events = [];

    // Helper to add events if timestamp is valid
    const addEventWithTimestamp = (item: any, type: string, timestampField: string = 'timestamp') => {
      const timestamp = item[timestampField];
      if (timestamp !== undefined && timestamp !== null && (typeof timestamp === 'string' || typeof timestamp === 'number')) {
        // Ensure timestamp is a string for consistency if it's a number (like epoch)
        events.push({ timestamp: String(timestamp), type });
      } else {
        console.warn(`Event of type '${type}' excluded from timeline due to missing or invalid timestamp:`, item);
      }
    };
    
    // Threat Detections (Alert type - assuming 'timestamp' exists and is valid)
    // The task description says Alert has severity, and implies timestamp.
    // The actual Alert type in usePacketSnifferSocket.ts is { message: string, timestamp: string; }
    (threatDetections || []).forEach(t => addEventWithTimestamp(t, "threat", "timestamp"));

    // HTTP Activities (HttpActivity type - assuming 'timestamp' exists, might be number)
    // HttpActivity type in usePacketSnifferSocket.ts is { endpoint: string; method: string; statusCode: number; } - NO TIMESTAMP!
    // This was an error in previous steps or assumption. HttpActivity in socketSlice.ts does NOT have timestamp.
    // For now, these will be excluded unless the type definition in socketSlice or the data itself includes a timestamp.
    // The `httpActivities` from `state.socket.httpActivities` uses `HttpActivity` from `@/alert/types` which is:
    // export interface HttpActivity { id: string; path: string; method: string; statusCode: number; timestamp: string; }
    // So, it *does* have a timestamp.
    (httpActivities || []).forEach(h => addEventWithTimestamp(h, "http", "timestamp"));

    // Packet Analyses (PacketMetadata type - 'timestamp' is number)
    (packetAnalyses || []).forEach(p => addEventWithTimestamp(p, "packet", "timestamp"));

    // Recent Critical Alerts (Alert type - 'timestamp' exists)
    (recentCriticalAlerts || []).forEach(a => addEventWithTimestamp(a, "critical_alert", "timestamp"));

    // Event types that LACK a timestamp field in their current definitions in usePacketSnifferSocket.ts:
    // - PhishingData: { url: string; confidence: number; }
    // - FirewallEvent: { ip: string; type: 'block' | 'allow'; reason: string; }
    // - DnsQuery: { domain: string; recordType: string; }
    // - ThreatResponse: { action: string; target: string; success: boolean; }
    // - FileQuarantined: { path: string; hash: string; reason: string; }
    // - IPv6Activity: { source: string; destination: string; payloadSize: number; }
    // These will be logged and excluded by addEventWithTimestamp if no valid timestamp field is found.
    
    if (process.env.NODE_ENV === 'development') {
        (phishingDetections || []).forEach(p => { if (!p.timestamp) console.warn("PhishingDetection event lacks 'timestamp'. Excluding from timeline:", p); });
        (firewallEvents || []).forEach(f => { if (!f.timestamp) console.warn("FirewallEvent event lacks 'timestamp'. Excluding from timeline:", f); });
        (dnsActivities || []).forEach(d => { if (!d.timestamp) console.warn("DnsActivity event lacks 'timestamp'. Excluding from timeline:", d); });
        (threatResponses || []).forEach(r => { if (!r.timestamp) console.warn("ThreatResponse event lacks 'timestamp'. Excluding from timeline:", r); });
        (quarantinedFiles || []).forEach(q => { if (!q.timestamp) console.warn("QuarantinedFile event lacks 'timestamp'. Excluding from timeline:", q); });
        (ipv6Activities || []).forEach(i => { if (!i.timestamp) console.warn("IPv6Activity event lacks 'timestamp'. Excluding from timeline:", i); });
    }


    return events;
  }, [
    threatDetections, 
    httpActivities, 
    packetAnalyses, 
    recentCriticalAlerts,
    // Add other event arrays here if they are supposed to have timestamps
    phishingDetections, firewallEvents, dnsActivities, threatResponses, quarantinedFiles, ipv6Activities 
  ]);

  // Helper function to ensure timestamp is a string for components that expect it.
  // This remains useful for table components that might expect string timestamps.
  // This is a temporary fix. Ideally, all event types should have a consistent timestamp property.
  // const ensureStringTimestamp = (data: any[], timestampField: string = 'timestamp') => {
  //   return data.map(item => ({ ...item, timestamp: String(item[timestampField] || new Date(0).toISOString()) }));
  // };
  
  // Review safe* transformations based on refined types (Task 7c)
  // Most backend types now include `id` and `timestamp` as ISO strings.
  // PhishingData now includes `severity`.

  // Assuming ThreatDetectionsTable expects `Alert[]` which is now refined.
  const safeThreatDetections = threatDetections; // Direct use if Alert has string timestamp

  // PhishingData is refined with timestamp and severity
  const safePhishingDetections = phishingDetections; 

  // FirewallActivityData is refined with timestamp
  const safeFirewallEvents = firewallEvents;

  // DnsActivityData is refined with timestamp
  const safeDnsActivities = dnsActivities; 

  // PacketMetadata's timestamp is still number, so conversion might be needed if table expects string.
  // Assuming PacketAnalysisTable can handle number timestamp or has internal formatting.
  // Or, if it must be string:
  const safePacketAnalyses = packetAnalyses.map(pA => ({...pA, timestamp: String(pA.timestamp)}));

  // IPv6Activity is refined with timestamp
  const safeIPv6Activities = ipv6Activities; 

  // ThreatResponse is refined with timestamp
  const safeThreatResponses = threatResponses; 

  // FileQuarantined is refined with timestamp
  const safeQuarantinedFiles = quarantinedFiles; 

  // Alert type (for recentCriticalAlerts) is refined with string timestamp
  const safeRecentCriticalAlerts = recentCriticalAlerts;


  const toggleSection = (section: keyof typeof sectionsExpanded) => {
    setSectionsExpanded(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };
  
  const handleRefresh = () => {
    toast({
      title: "Dashboard Refreshed",
      description: "Security data has been updated with latest information.",
    });
  };

  const handleExport = () => {
    toast({
      title: "Report Generated",
      description: "Security report has been prepared for download.",
    });
  };




  return (
    <div className="min-h-screen bg-background p-2 sm:p-4 md:p-8">
      <header className="mb-4 md:mb-8 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center mb-2">
            <Shield className="w-6 h-6 sm:w-8 sm:h-8 mr-2 sm:mr-3 text-primary" />
            <h1 className="text-xl sm:text-2xl md:text-3xl font-bold">Monitor alerts in real time</h1>
          </div>
          <p className="text-sm md:text-base text-muted-foreground max-w-3xl">
            All alerts and warnings appear here!
          </p>
        </div>
        <div className="flex items-center gap-2 sm:gap-3 self-end md:self-auto">
          <Button variant="outline" size="sm" className="text-xs sm:text-sm" onClick={handleRefresh}>
            <RefreshCcw className="w-3 h-3 sm:w-4 sm:h-4 mr-1 sm:mr-2" />
            <span className="hidden xs:inline">Refresh</span>
          </Button>
          <Button variant="outline" size="sm" className="text-xs sm:text-sm" onClick={handleExport}>
            <Download className="w-3 h-3 sm:w-4 sm:h-4 mr-1 sm:mr-2" />
            <span className="hidden xs:inline">Export Report</span>
          </Button>
        </div>
      </header>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4 md:gap-6 mb-6 md:mb-8">
        <Card className="col-span-1 md:col-span-2 lg:col-span-1 transition-all duration-200 hover:shadow-lg">
          <CardHeader className="pb-2 px-3 sm:px-6">
            <CardTitle className="text-base sm:text-lg font-medium">Threat Level</CardTitle>
          </CardHeader>
          <CardContent className="flex justify-center px-3 sm:px-6">
            <ThreatLevelIndicator
              level={currentThreatLevel}
              description={currentThreatLevelData.description}
            />
          </CardContent>
        </Card>

        <ThreatsCountCard threatCounts={activeThreatCounts} className="transition-all duration-200 hover:shadow-lg" />
        <SystemHealthCard systems={systemStatusData} className="md:col-span-2 lg:col-span-1 transition-all duration-200 hover:shadow-lg" />

      </div>

      <div className="mb-6 md:mb-8">
        <RecentAlertsCard alerts={safeRecentCriticalAlerts} className="transition-all duration-200 hover:shadow-lg" />
      </div>

      <div className="mb-6 md:mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg sm:text-xl md:text-2xl font-bold flex items-center">
            <AlertCircle className="w-4 h-4 sm:w-5 sm:h-5 mr-2 text-threat-medium" />
            Threat Intelligence
          </h2>
          <Button 
            variant="ghost" 
            size="sm" 
            className="p-1 h-6 sm:h-8" 
            onClick={() => toggleSection("threatIntelligence")}
          >
            {sectionsExpanded.threatIntelligence ? <ChevronUp className="w-4 h-4 sm:w-5 sm:h-5" /> : <ChevronDown className="w-4 h-4 sm:w-5 sm:h-5" />}
          </Button>
        </div>
        
        {sectionsExpanded.threatIntelligence && (
          <Tabs defaultValue="threats" value={activeTab} onValueChange={setActiveTab} className="w-full overflow-x-auto">
            <TabsList className="mb-4 w-full justify-start">
              <TabsTrigger value="threats" className="text-xs sm:text-sm">Threat Detections</TabsTrigger>
              <TabsTrigger value="phishing" className="text-xs sm:text-sm">Phishing & URL Analysis</TabsTrigger>
              <TabsTrigger value="firewall" className="text-xs sm:text-sm">Firewall Events</TabsTrigger>
            </TabsList>
            
            <TabsContent value="threats" className="animate-slide-in">
              <div className="overflow-x-auto">
                <ThreatDetectionsTable threats={safeThreatDetections} />
              </div>
            </TabsContent>
            
            <TabsContent value="phishing" className="animate-slide-in">
              <div className="overflow-x-auto">
                <PhishingDetectionsTable detections={safePhishingDetections} />
              </div>
            </TabsContent>
            
            <TabsContent value="firewall" className="animate-slide-in">
              <div className="space-y-6 overflow-x-auto">
                <FirewallEventsTable events={safeFirewallEvents} />
              </div>
            </TabsContent>
          </Tabs>
        )}
      </div>

      <Separator className="my-4 sm:my-6" />
      
      {/* Network Monitoring Section */}
      <div className="mb-6 md:mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg sm:text-xl md:text-2xl font-bold flex items-center">
            <AlertCircle className="w-4 h-4 sm:w-5 sm:h-5 mr-2 text-primary" />
            Network Activity Monitoring
          </h2>
          <Button 
            variant="ghost" 
            size="sm" 
            className="p-1 h-6 sm:h-8" 
            onClick={() => toggleSection("networkActivity")}
          >
            {sectionsExpanded.networkActivity ? <ChevronUp className="w-4 h-4 sm:w-5 sm:h-5" /> : <ChevronDown className="w-4 h-4 sm:w-5 sm:h-5" />}
          </Button>
        </div>
        
        {sectionsExpanded.networkActivity && (
          <Tabs defaultValue="http" value={networkActiveTab} onValueChange={setNetworkActiveTab} className="w-full overflow-x-auto">
            <TabsList className="mb-4 w-full justify-start overflow-x-auto flex-nowrap">
              <TabsTrigger value="http" className="text-xs sm:text-sm">HTTP Activity</TabsTrigger>
              <TabsTrigger value="dns" className="text-xs sm:text-sm">DNS Monitoring</TabsTrigger>
              <TabsTrigger value="packets" className="text-xs sm:text-sm">Packet Analysis</TabsTrigger>
              <TabsTrigger value="ipv6" className="text-xs sm:text-sm">IPv6 Activity</TabsTrigger>
            </TabsList>
            
            <TabsContent value="http" className="animate-slide-in">
              <div className="space-y-6 overflow-x-auto">
                <Card className="mb-6">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="text-base sm:text-lg">HTTP Activity Monitor</CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <p className="mb-4 text-xs sm:text-sm text-muted-foreground">
                      Monitors HTTP requests, analyzes headers, detects injection attempts, and calculates threat scores based on behavioral analysis.
                    </p>
                    <div className="overflow-x-auto">
                      <HttpActivityTable activities={httpActivities} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="dns" className="animate-slide-in">
              <div className="space-y-6">
                <Card className="mb-6">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="text-base sm:text-lg">DNS Activity Monitor</CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <p className="mb-4 text-xs sm:text-sm text-muted-foreground">
                      Tracks DNS queries, identifies potentially malicious domains, detects unusual TTL values, and correlates with threat intelligence feeds.
                    </p>
                    <div className="overflow-x-auto">
                      <DnsActivityTable activities={safeDnsActivities} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="packets" className="animate-slide-in">
              <div className="space-y-6">
                <Card className="mb-6">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="text-base sm:text-lg">Network Packet Analysis</CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <p className="mb-4 text-xs sm:text-sm text-muted-foreground">
                      Analyzes packets for suspicious characteristics, monitors protocol distributions, and detects network anomalies like port scans.
                    </p>
                    <div className="overflow-x-auto">
                      <PacketAnalysisTable packets={safePacketAnalyses} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="ipv6" className="animate-slide-in">
              <div className="space-y-6">
                <Card className="mb-6">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="text-base sm:text-lg">IPv6 Traffic Analysis</CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <p className="mb-4 text-xs sm:text-sm text-muted-foreground">
                      Monitors IPv6 traffic patterns, detects baseline deviations, and identifies potential tunneled traffic for evading security controls.
                    </p>
                    <div className="overflow-x-auto">
                      <IPv6ActivityTable activities={safeIPv6Activities} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        )}
      </div>
      
      <Separator className="my-4 sm:my-6" />

      {/* Automated Responses Section */}
      <div className="mb-6 md:mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg sm:text-xl md:text-2xl font-bold flex items-center">
            <AlertCircle className="w-4 h-4 sm:w-5 sm:h-5 mr-2 text-threat-low" />
            Automated Responses
          </h2>
          <Button 
            variant="ghost" 
            size="sm" 
            className="p-1 h-6 sm:h-8" 
            onClick={() => toggleSection("automatedResponses")}
          >
            {sectionsExpanded.automatedResponses ? <ChevronUp className="w-4 h-4 sm:w-5 sm:h-5" /> : <ChevronDown className="w-4 h-4 sm:w-5 sm:h-5" />}
          </Button>
        </div>
        
        {sectionsExpanded.automatedResponses && (
          <Tabs defaultValue="responses" value={automatedResponsesActiveTab} onValueChange={setAutomatedResponsesActiveTab} className="w-full overflow-x-auto">
            <TabsList className="mb-4 w-full justify-start">
              <TabsTrigger value="responses" className="text-xs sm:text-sm">Threat Responses</TabsTrigger>
              <TabsTrigger value="quarantined" className="text-xs sm:text-sm">Quarantined Files</TabsTrigger>
            </TabsList>
            
            <TabsContent value="responses" className="animate-slide-in">
              <div className="space-y-6">
                <Card className="mb-6">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="text-base sm:text-lg">Security Response Actions</CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <p className="mb-4 text-xs sm:text-sm text-muted-foreground">
                      Records of automated security actions taken in response to detected threats, including IP blocks, process termination, and more.
                    </p>
                    <div className="overflow-x-auto">
                      <ThreatResponseTable responses={safeThreatResponses} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
            
            <TabsContent value="quarantined" className="animate-slide-in">
              <div className="space-y-6">
                <Card className="mb-6">
                  <CardHeader className="px-3 sm:px-6">
                    <CardTitle className="text-base sm:text-lg">Quarantined Files</CardTitle>
                  </CardHeader>
                  <CardContent className="px-3 sm:px-6">
                    <p className="mb-4 text-xs sm:text-sm text-muted-foreground">
                      Files automatically quarantined due to detection of malicious content, suspicious behavior, or unauthorized modifications.
                    </p>
                    <div className="overflow-x-auto">
                      <QuarantinedFilesTable files={safeQuarantinedFiles} />
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>
        )}
      </div>
      
      <Separator className="my-4 sm:my-6" />

      {/* Historical & Trends View */}
      <div className="mb-6 md:mb-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg sm:text-xl md:text-2xl font-bold flex items-center">
            <AlertCircle className="w-4 h-4 sm:w-5 sm:h-5 mr-2 text-primary" />
            Security History & Trends
          </h2>
          <Button 
            variant="ghost" 
            size="sm" 
            className="p-1 h-6 sm:h-8" 
            onClick={() => toggleSection("history")}
          >
            {sectionsExpanded.history ? <ChevronUp className="w-4 h-4 sm:w-5 sm:h-5" /> : <ChevronDown className="w-4 h-4 sm:w-5 sm:h-5" />}
          </Button>
        </div>
        
        {sectionsExpanded.history && (
          <div className="grid grid-cols-1 gap-4 md:gap-6">
            <SecurityHistoryTimeline 
              threats={safeThreatDetections}
              phishing={safePhishingDetections}
              firewall={safeFirewallEvents}
              http={httpActivities || []} // httpActivities is already from redux
              dns={safeDnsActivities}
              packets={safePacketAnalyses}
              responses={safeThreatResponses}
              quarantined={safeQuarantinedFiles}
              ipv6={safeIPv6Activities}
              className="transition-all duration-200 hover:shadow-lg"
            />
            
            <EventHeatMap data={allTimelineEvents} className="transition-all duration-200 hover:shadow-lg" />
          </div>
        )}
      </div>
      
    </div>
  );
};

export default Index;
