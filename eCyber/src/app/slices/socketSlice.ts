import { createSlice, PayloadAction } from '@reduxjs/toolkit';
// Import refined types from the single source of truth
import { 
    SocketEvent, // This type itself should be imported if it's canonical in useSocket.ts
    HttpActivity,
    Alert, // General refined Alert
    ThreatData, // If this is distinct from Alert and still used
    PhishingData,
    TrainingProgress,
    NetworkAnomaly,
    AccessData,
    FirewallActivityData, // Using the new consolidated type
    UrlClassification,
    ServiceStatus,
    DnsActivityData, // Using the new consolidated type
    ErrorData,
    SshConnection,
    Rule,
    SystemStats,
    SystemStatus,
    IPv6Activity,
    // CriticalAlert, // This is now just 'Alert' with high severity
    SystemTelemetry,
    ThreatResponse,
    ProcessInspection,
    ConnectionAnalysis,
    FileQuarantined,
    SystemSnapshot,
    PacketMetadata, // Assuming this is the refined PacketMetadata for packet_data events
    TcpActivityData, // Refined type
    UdpActivityData, // Refined type
    IcmpActivityData, // Refined type
    ArpActivityData, // Refined type
    PayloadAnalysisData, // Refined type
    BehaviorAnalysisData // Refined type
} from '@/hooks/usePacketSnifferSocket'; // Adjusted path assuming usePacketSnifferSocket is in hooks dir

// Note: Original local definitions for FirewallData, DnsQuery, etc., are removed in favor of imported ones.
// If some of these types in socketSlice.ts had fields not present in usePacketSnifferSocket.ts versions,
// those fields might be lost unless the usePacketSnifferSocket.ts versions were made comprehensive.

interface SocketState {
  isConnected: boolean;
  connectionError: string | null;
  // Security events
  threats: ThreatData[]; // Keep if ThreatData is a distinct, richer type than general Alert for 'threat_detected'
  firewallEvents: FirewallActivityData[]; // Use consolidated type
  phishingLinks: PhishingData[]; // Use refined PhishingData
  unauthorizedAccess: AccessData[];
  criticalAlerts: Alert[]; // Use refined Alert (critical_alert events now send refined Alert)
  securityAlerts: Alert[]; // Use refined Alert
  fileQuarantines: FileQuarantined[];
  threatResponses: ThreatResponse[];
  
  // Network events
  networkAnomalies: NetworkAnomaly[];
  httpActivities: HttpActivity[]; // Use refined HttpActivity
  dnsQueries: DnsActivityData[]; // Use refined DnsActivityData (holds more than just queries)
  ipv6Activities: IPv6Activity[]; // Use refined IPv6Activity
  packetData: PacketMetadata[]; // Use refined PacketMetadata
  connectionAnalyses: ConnectionAnalysis[];
  tcpActivities: TcpActivityData[]; // Use refined TcpActivityData
  udpActivities: UdpActivityData[]; // Use refined UdpActivityData
  icmpActivities: IcmpActivityData[]; // Use refined IcmpActivityData
  arpActivities: ArpActivityData[]; // Use refined ArpActivityData
  payloadAnalysisEvents: PayloadAnalysisData[]; // Use refined PayloadAnalysisData
  behaviorAnalysisEvents: BehaviorAnalysisData[]; // Use refined BehaviorAnalysisData
  
  // System events
  systemStatsOld: SystemStats[]; // Keeping old one if structure was different, mark for review/removal
  systemStats: SystemStats | null; // For the new single object SystemStats
  systemStatus: SystemStatus | null;
  systemTelemetry: SystemTelemetry[]; // This is an array from backend.
  systemErrors: ErrorData[];
  serviceStatuses: ServiceStatus[];
  processInspections: ProcessInspection[];
  
  // Training events
  trainingProgress: TrainingProgress | null;
  trainingCompleted: boolean;
  
  // Other events
  urlClassifications: UrlClassification[];
  firewallBlocks: FirewallActivityData[]; // Use consolidated type
  sshConnections: SshConnection[];
  rules: Rule[];
  systemSnapshots: SystemSnapshot[];
  
  // Latest event timestamps
  lastUpdated: {
    [key in SocketEvent['type']]?: string;
  };
}

const initialState: SocketState = {
  isConnected: false,
  connectionError: null,
  threats: [],
  firewallEvents: [], // Should be FirewallActivityData[]
  phishingLinks: [],
  unauthorizedAccess: [],
  criticalAlerts: [], // Should be Alert[]
  securityAlerts: [], // Should be Alert[]
  fileQuarantines: [],
  threatResponses: [],
  networkAnomalies: [],
  httpActivities: JSON.parse(localStorage.getItem('httpActivity')) || [], // Should be HttpActivity[]
  dnsQueries: [], // Should be DnsActivityData[]
  ipv6Activities: [], // Should be IPv6Activity[]
  packetData: [], // Should be PacketMetadata[]
  connectionAnalyses: [],
  tcpActivities: [],
  udpActivities: [],
  icmpActivities: [],
  arpActivities: [],
  payloadAnalysisEvents: [],
  behaviorAnalysisEvents: [],
  systemStatsOld: [], // Initialize if keeping
  systemStats: null, // Initialize new single object SystemStats
  systemStatus: null,
  systemTelemetry: [],
  systemErrors: [],
  serviceStatuses: [],
  processInspections: [],
  trainingProgress: null,
  trainingCompleted: false,
  urlClassifications: [],
  firewallBlocks: [],
  sshConnections: [],
  rules: [],
  systemSnapshots: [],
  lastUpdated: {},
};

const socketSlice = createSlice({
  name: 'socket',
  initialState,
  reducers: {
    // Connection management
    setConnectionStatus(state, action: PayloadAction<boolean>) {
      state.isConnected = action.payload;
    },
    setConnectionError(state, action: PayloadAction<string | null>) {
      state.connectionError = action.payload;
    },
    
    // Security event reducers
    addThreat(state, action: PayloadAction<ThreatData>) {
      state.threats.push(action.payload);
      state.lastUpdated['threat_detected'] = new Date().toISOString();
    },
    addFirewallEvent(state, action: PayloadAction<FirewallActivityData>) { // Use FirewallActivityData
      state.firewallEvents.push(action.payload); // This is now FirewallActivityData[]
      state.lastUpdated['firewall_event'] = new Date().toISOString();
    },
    addPhishingLink(state, action: PayloadAction<PhishingData>) { // Use refined PhishingData
      state.phishingLinks.push(action.payload);
      state.lastUpdated['phishing_link_detected'] = new Date().toISOString();
    },
    addUnauthorizedAccess(state, action: PayloadAction<AccessData>) {
      state.unauthorizedAccess.push(action.payload);
      state.lastUpdated['unauthorized_access'] = new Date().toISOString();
    },
    addCriticalAlert(state, action: PayloadAction<Alert>) { // Use refined Alert
      state.criticalAlerts.push(action.payload);
      state.lastUpdated['critical_alert'] = new Date().toISOString();
    },
    addSecurityAlert(state, action: PayloadAction<Alert>) { // Use refined Alert
      state.securityAlerts.push(action.payload);
      state.lastUpdated['security_alert'] = new Date().toISOString();
    },
    addFileQuarantine(state, action: PayloadAction<FileQuarantined>) {
      state.fileQuarantines.push(action.payload);
      state.lastUpdated['file_quarantined'] = new Date().toISOString();
    },
    addThreatResponse(state, action: PayloadAction<ThreatResponse>) {
      state.threatResponses.push(action.payload);
      state.lastUpdated['threat_response'] = new Date().toISOString();
    },
    
    // Network event reducers
    addNetworkAnomaly(state, action: PayloadAction<NetworkAnomaly>) {
      state.networkAnomalies.push(action.payload);
      state.lastUpdated['network_anomaly'] = new Date().toISOString();
    },
    addHttpActivity(state, action: PayloadAction<HttpActivity>) { // Use refined HttpActivity
      // Assuming HttpActivity always has an id now, and path might be optional if not applicable
      // The old check for action.payload.path might need re-evaluation based on refined HttpActivity type
      if (!action.payload.id) return; // Example: ensure an ID is present
    
      state.httpActivities.push(action.payload);
    
      // Keep only the last X records
      if (state.httpActivities.length > 20) { // Increased slightly
        state.httpActivities = state.httpActivities.slice(-20);
      }
    
      state.lastUpdated['http_activity'] = new Date().toISOString();
    
      // Storing to localStorage might need to be reviewed based on data sensitivity/size
      // const activitiesWithPath = state.httpActivities.filter(item => item.path); // if path is still a primary filter
      localStorage.setItem('httpActivity', JSON.stringify(state.httpActivities));
    },       
    addDnsQuery(state, action: PayloadAction<DnsActivityData>) { // Use DnsActivityData
      state.dnsQueries.push(action.payload); // This is now DnsActivityData[]
      state.lastUpdated['dns_activity'] = new Date().toISOString();
    },
    addIpv6Activity(state, action: PayloadAction<IPv6Activity>) { // Use refined IPv6Activity
      state.ipv6Activities.push(action.payload);
      state.lastUpdated['ipv6_activity'] = new Date().toISOString();
    },
    addPacketData(state, action: PayloadAction<PacketMetadata>) { // Use refined PacketMetadata
      state.packetData.push(action.payload);
      state.lastUpdated['packet_data'] = new Date().toISOString();
    },
    addConnectionAnalysis(state, action: PayloadAction<ConnectionAnalysis>) {
      state.connectionAnalyses.push(action.payload);
      state.lastUpdated['connection_analysis'] = new Date().toISOString();
    },
    addTcpActivity(state, action: PayloadAction<TcpActivityData>) {
      state.tcpActivities = [action.payload, ...state.tcpActivities].slice(0, 150);
      state.lastUpdated['tcp_activity'] = new Date().toISOString();
    },
    addUdpActivity(state, action: PayloadAction<UdpActivityData>) {
      state.udpActivities = [action.payload, ...state.udpActivities].slice(0, 150);
      state.lastUpdated['udp_activity'] = new Date().toISOString();
    },
    addIcmpActivity(state, action: PayloadAction<IcmpActivityData>) {
      state.icmpActivities = [action.payload, ...state.icmpActivities].slice(0, 100);
      state.lastUpdated['icmp_activity'] = new Date().toISOString();
    },
    addArpActivity(state, action: PayloadAction<ArpActivityData>) {
      state.arpActivities = [action.payload, ...state.arpActivities].slice(0, 100);
      state.lastUpdated['arp_activity'] = new Date().toISOString();
    },
    addPayloadAnalysisEvent(state, action: PayloadAction<PayloadAnalysisData>) {
      state.payloadAnalysisEvents = [action.payload, ...state.payloadAnalysisEvents].slice(0, 100);
      state.lastUpdated['payload_analysis_event'] = new Date().toISOString();
    },
    addBehaviorAnalysisEvent(state, action: PayloadAction<BehaviorAnalysisData>) {
      state.behaviorAnalysisEvents = [action.payload, ...state.behaviorAnalysisEvents].slice(0, 100);
      state.lastUpdated['behavior_analysis_event'] = new Date().toISOString();
    },
    
    // System event reducers
    // Note: systemStats was an array, but the refined SystemStats is likely a single object.
    // The realtimeDataSlice handles systemStats and systemStatus now.
    // These reducers in socketSlice might be deprecated or need to align with realtimeDataSlice's handling.
    // For now, I'll update the type for addSystemStat assuming it's for the new single object type.
    // If systemStats here is meant to be an array of historical stats, its type and name should differ from realtimeDataSlice.systemMetrics.systemStats
    
    // Assuming systemStatsOld is for the array of historical stats
    addSystemStatOld(state, action: PayloadAction<SystemStats>) { // This SystemStats should be the one for array items
      state.systemStatsOld.push(action.payload);
      if (state.systemStatsOld.length > 100) state.systemStatsOld.shift(); 
      // state.lastUpdated['system_stats'] = new Date().toISOString(); // This key might conflict
    },
    // This reducer updates the single SystemStats object, similar to realtimeDataSlice.
    updateSystemStats(state, action: PayloadAction<SystemStats>) { // Use refined SystemStats
      state.systemStats = action.payload;
      state.lastUpdated['system_stats'] = new Date().toISOString();
    },
    setSystemStatus(state, action: PayloadAction<SystemStatus>) { // Use refined SystemStatus
      state.systemStatus = action.payload;
      state.lastUpdated['system_status'] = new Date().toISOString();
    },
    addSystemTelemetry(state, action: PayloadAction<SystemTelemetry[]>) { // Assuming SystemTelemetry itself was refined with id/timestamp
      state.systemTelemetry = action.payload; // This replaces the whole array
      state.lastUpdated['system_telemetry'] = new Date().toISOString();
    },
    addSystemError(state, action: PayloadAction<ErrorData>) {
      state.systemErrors.push(action.payload);
      state.lastUpdated['system_error'] = new Date().toISOString();
    },
    addServiceStatus(state, action: PayloadAction<ServiceStatus>) {
      state.serviceStatuses.push(action.payload);
      state.lastUpdated['service_status'] = new Date().toISOString();
    },
    addProcessInspection(state, action: PayloadAction<ProcessInspection>) {
      state.processInspections.push(action.payload);
      state.lastUpdated['process_inspection'] = new Date().toISOString();
    },
    
    // Training event reducers
    setTrainingProgress(state, action: PayloadAction<TrainingProgress>) {
      state.trainingProgress = action.payload;
      state.lastUpdated['training_progress'] = new Date().toISOString();
    },
    setTrainingCompleted(state) {
      state.trainingCompleted = true;
      state.lastUpdated['training_completed'] = new Date().toISOString();
    },
    
    // Other event reducers
    addUrlClassification(state, action: PayloadAction<UrlClassification>) {
      state.urlClassifications.push(action.payload);
      state.lastUpdated['url_classification_result'] = new Date().toISOString();
    },
    addFirewallBlock(state, action: PayloadAction<FirewallData>) {
      state.firewallBlocks.push(action.payload);
      state.lastUpdated['firewall_blocked'] = new Date().toISOString();
    },
    addSshConnection(state, action: PayloadAction<SshConnection>) {
      state.sshConnections.push(action.payload);
      state.lastUpdated['ssh_connection'] = new Date().toISOString();
    },
    setRules(state, action: PayloadAction<Rule[]>) {
      state.rules = action.payload;
      state.lastUpdated['get_rules'] = new Date().toISOString();
    },
    addSystemSnapshot(state, action: PayloadAction<SystemSnapshot>) {
      state.systemSnapshots.push(action.payload);
      state.lastUpdated['system_snapshot'] = new Date().toISOString();
    },
    
    // Clear actions for when you need to reset certain state
    clearThreats(state) {
      state.threats = [];
    },
    clearFirewallEvents(state) {
      state.firewallEvents = [];
    },
    clearNetworkAnomalies(state) {
      state.networkAnomalies = [];
    },
    clearAll(state) {
      return { ...initialState, isConnected: state.isConnected };
    },
    
    // Generic event handler that can handle any SocketEvent
    handleSocketEvent(state, action: PayloadAction<SocketEvent>) {
      const { type, data } = action.payload;
      state.lastUpdated[type] = new Date().toISOString();
    },
  },
});

// Export all actions
export const {
  setConnectionStatus,
  setConnectionError,
  addThreat,
  addFirewallEvent,
  addPhishingLink,
  addUnauthorizedAccess,
  addCriticalAlert,
  addSecurityAlert,
  addFileQuarantine,
  addThreatResponse,
  addNetworkAnomaly,
  addHttpActivity,
  addDnsQuery,
  addIpv6Activity,
  addPacketData,
  addConnectionAnalysis,
  addTcpActivity,
  addUdpActivity,
  addIcmpActivity,
  addArpActivity,
  addPayloadAnalysisEvent,
  addBehaviorAnalysisEvent,
  addSystemStat,
  setSystemStatus,
  addSystemTelemetry,
  addSystemError,
  addServiceStatus,
  addProcessInspection,
  setTrainingProgress,
  setTrainingCompleted,
  addUrlClassification,
  addFirewallBlock,
  addSshConnection,
  setRules,
  addSystemSnapshot,
  clearThreats,
  clearFirewallEvents,
  clearNetworkAnomalies,
  clearAll,
  handleSocketEvent,
} = socketSlice.actions;

export default socketSlice.reducer;