import { useEffect } from 'react';
import { useDispatch } from 'react-redux';
import { usePacketSnifferSocket } from './usePacketSnifferSocket';
import { useFirewallSocket } from './useFirewallSocket';
import {
  addThreat,
  addFirewallEvent,
  setConnectionStatus,
  setConnectionError,
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
} from '../features/socket/socketSlice';

export function useSocketManager() {
  const dispatch = useDispatch();

  // Get individual sockets
  const packetSniffer = usePacketSnifferSocket();
  const firewall = useFirewallSocket();

  useEffect(() => {
    // Connect all sockets
    packetSniffer.connect();
    firewall.connect();

    // Connection status handlers
    const handleConnectionChange = (isConnected: boolean) => {
      dispatch(setConnectionStatus(isConnected));
    };

    const handleConnectionError = (error: string | null) => {
      dispatch(setConnectionError(error));
    };

    // Subscribe to connection status changes if available
    if (packetSniffer.onConnectionChange) {
      packetSniffer.onConnectionChange(handleConnectionChange);
    }
    if (packetSniffer.onConnectionError) {
      packetSniffer.onConnectionError(handleConnectionError);
    }

    // Security event handlers
    const threatHandler = (data: any) => dispatch(addThreat(data));
    const phishingHandler = (data: any) => dispatch(addPhishingLink(data));
    const unauthorizedAccessHandler = (data: any) => dispatch(addUnauthorizedAccess(data));
    const criticalAlertHandler = (data: any) => dispatch(addCriticalAlert(data));
    const securityAlertHandler = (data: any) => dispatch(addSecurityAlert(data));
    const fileQuarantineHandler = (data: any) => dispatch(addFileQuarantine(data));
    const threatResponseHandler = (data: any) => dispatch(addThreatResponse(data));

    // Network event handlers
    const firewallEventHandler = (data: any) => dispatch(addFirewallEvent(data));
    const networkAnomalyHandler = (data: any) => dispatch(addNetworkAnomaly(data));
    const httpActivityHandler = (data: any) => dispatch(addHttpActivity(data));
    const dnsQueryHandler = (data: any) => dispatch(addDnsQuery(data));
    const ipv6ActivityHandler = (data: any) => dispatch(addIpv6Activity(data));
    const packetDataHandler = (data: any) => dispatch(addPacketData(data));
    const connectionAnalysisHandler = (data: any) => dispatch(addConnectionAnalysis(data));

    // System event handlers
    const systemStatHandler = (data: any) => dispatch(addSystemStat(data));
    const systemStatusHandler = (data: any) => dispatch(setSystemStatus(data));
    const systemTelemetryHandler = (data: any) => dispatch(addSystemTelemetry(data));
    const systemErrorHandler = (data: any) => dispatch(addSystemError(data));
    const serviceStatusHandler = (data: any) => dispatch(addServiceStatus(data));
    const processInspectionHandler = (data: any) => dispatch(addProcessInspection(data));

    // Training event handlers
    const trainingProgressHandler = (data: any) => dispatch(setTrainingProgress(data));
    const trainingCompletedHandler = () => dispatch(setTrainingCompleted());

    // Other event handlers
    const urlClassificationHandler = (data: any) => dispatch(addUrlClassification(data));
    const firewallBlockHandler = (data: any) => dispatch(addFirewallBlock(data));
    const sshConnectionHandler = (data: any) => dispatch(addSshConnection(data));
    const rulesHandler = (data: any) => dispatch(setRules(data));
    const systemSnapshotHandler = (data: any) => dispatch(addSystemSnapshot(data));

    // Subscribe to all packet sniffer events
    packetSniffer.subscribe('threat_detected', threatHandler);
    packetSniffer.subscribe('phishing_link_detected', phishingHandler);
    packetSniffer.subscribe('unauthorized_access', unauthorizedAccessHandler);
    packetSniffer.subscribe('critical_alert', criticalAlertHandler);
    packetSniffer.subscribe('security_alert', securityAlertHandler);
    packetSniffer.subscribe('file_quarantined', fileQuarantineHandler);
    packetSniffer.subscribe('threat_response', threatResponseHandler);
    packetSniffer.subscribe('network_anomaly', networkAnomalyHandler);
    packetSniffer.subscribe('http_activity', httpActivityHandler);
    packetSniffer.subscribe('dns_activity', dnsQueryHandler);
    packetSniffer.subscribe('ipv6_activity', ipv6ActivityHandler);
    packetSniffer.subscribe('packet_data', packetDataHandler);
    packetSniffer.subscribe('connection_analysis', connectionAnalysisHandler);
    packetSniffer.subscribe('system_stats', systemStatHandler);
    packetSniffer.subscribe('system_status', systemStatusHandler);
    packetSniffer.subscribe('system_telemetry', systemTelemetryHandler);
    packetSniffer.subscribe('system_error', systemErrorHandler);
    packetSniffer.subscribe('service_status', serviceStatusHandler);
    packetSniffer.subscribe('process_inspection', processInspectionHandler);
    packetSniffer.subscribe('training_progress', trainingProgressHandler);
    packetSniffer.subscribe('training_completed', trainingCompletedHandler);
    packetSniffer.subscribe('url_classification_result', urlClassificationHandler);
    packetSniffer.subscribe('firewall_blocked', firewallBlockHandler);
    packetSniffer.subscribe('ssh_connection', sshConnectionHandler);
    packetSniffer.subscribe('get_rules', rulesHandler);
    packetSniffer.subscribe('system_snapshot', systemSnapshotHandler);

    // Subscribe to firewall-specific events
    firewall.subscribe('firewall_event', firewallEventHandler);

    return () => {
      // Unsubscribe from all packet sniffer events
      packetSniffer.unsubscribe('threat_detected', threatHandler);
      packetSniffer.unsubscribe('phishing_link_detected', phishingHandler);
      packetSniffer.unsubscribe('unauthorized_access', unauthorizedAccessHandler);
      packetSniffer.unsubscribe('critical_alert', criticalAlertHandler);
      packetSniffer.unsubscribe('security_alert', securityAlertHandler);
      packetSniffer.unsubscribe('file_quarantined', fileQuarantineHandler);
      packetSniffer.unsubscribe('threat_response', threatResponseHandler);
      packetSniffer.unsubscribe('network_anomaly', networkAnomalyHandler);
      packetSniffer.unsubscribe('http_activity', httpActivityHandler);
      packetSniffer.unsubscribe('dns_activity', dnsQueryHandler);
      packetSniffer.unsubscribe('ipv6_activity', ipv6ActivityHandler);
      packetSniffer.unsubscribe('packet_data', packetDataHandler);
      packetSniffer.unsubscribe('connection_analysis', connectionAnalysisHandler);
      packetSniffer.unsubscribe('system_stats', systemStatHandler);
      packetSniffer.unsubscribe('system_status', systemStatusHandler);
      packetSniffer.unsubscribe('system_telemetry', systemTelemetryHandler);
      packetSniffer.unsubscribe('system_error', systemErrorHandler);
      packetSniffer.unsubscribe('service_status', serviceStatusHandler);
      packetSniffer.unsubscribe('process_inspection', processInspectionHandler);
      packetSniffer.unsubscribe('training_progress', trainingProgressHandler);
      packetSniffer.unsubscribe('training_completed', trainingCompletedHandler);
      packetSniffer.unsubscribe('url_classification_result', urlClassificationHandler);
      packetSniffer.unsubscribe('firewall_blocked', firewallBlockHandler);
      packetSniffer.unsubscribe('ssh_connection', sshConnectionHandler);
      packetSniffer.unsubscribe('get_rules', rulesHandler);
      packetSniffer.unsubscribe('system_snapshot', systemSnapshotHandler);

      // Unsubscribe from firewall events
      firewall.unsubscribe('firewall_event', firewallEventHandler);

      // Clean up connection listeners
      if (packetSniffer.offConnectionChange) {
        packetSniffer.offConnectionChange(handleConnectionChange);
      }
      if (packetSniffer.offConnectionError) {
        packetSniffer.offConnectionError(handleConnectionError);
      }

      // Disconnect sockets
      packetSniffer.disconnect();
      firewall.disconnect();
    };
  }, [dispatch, packetSniffer, firewall]);

  // Optional: return the sockets if needed by components
  return { packetSniffer, firewall };
}