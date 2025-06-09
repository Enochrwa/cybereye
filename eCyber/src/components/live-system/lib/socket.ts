
import { io, Socket } from 'socket.io-client';
import { toast } from "sonner";


import { useInstantTransition } from 'framer-motion';
import { useTelemetryData } from './mock-data';

// CPU Details
export interface CPUDetails {
  cores: {
    physical: number;
    logical: number;
  };
  frequency: {
    current: number;
    min: number;
    max: number;
  };
  usage: number;
  times?: {
    user: number;
    system: number;
    idle: number;
    interrupt: number;
    dpc: number;
  };
}

// Memory Details
export interface MemoryDetails {
  total: number;
  used: number;
  available: number;
  percent: number;
  swap?: {
    total: number;
    used: number;
    percent: number;
  };
}

// IO Data
export interface IOData {
  timestamp: number;
  read: number;
  write: number;
}

// Network IO
export interface NetworkIOData {
  timestamp: number;
  sent: number;
  received: number;
}

// Disk IO Data
export interface DiskIOData {
  read: number[];
  write: number[];
  timestamps: string[];
}

// Status Item
export interface StatusItem {
  title: string;
  value: string | number;
  status: "normal" | "warning" | "critical" | "good";
  details?: string;
  trend?: "up" | "down" | "stable";
}

// System Overview Item
export interface SystemOverviewItem {
  title: string;
  value: string | number;
  color?: string;
  icon?: string;
  details?: string;
}

// Security Overview
export interface SecurityOverview {
  firewall: "Enabled" | "Disabled";
  suspiciousConnections: number;
  suspiciousProcesses: number;
  systemUpdates: "Enabled" | "Disabled";
}

// Chart Data Point
export interface DataPoint {
  timestamp: number;
  value: number;
}

// Network Interface
export interface NetworkInterface {
  name: string;
  ipAddress: string;
  macAddress: string;
  speed: number;
  is_up: boolean;
  status: "up" | "down";
  addresses: {
    family: string;
    address: string;
    netmask: string | null;
  }[];
  stats?: {
    bytes_sent: number;
    bytes_recv: number;
    packets_sent: number;
    packets_recv: number;
  };
}

// Process Item
export interface ProcessItem {
  pid: number;
  name: string;
  user: string;
  cpu: number;
  memory: number;
  status?: string;
  signed: boolean | null;
  suspicious: boolean;
}

// Network Connection
export interface NetworkConnection {
  localAddress: string;
  remoteAddress: string;
  status: string;
  pid: number;
  process: string;
  suspicious: boolean;
  isInternal: boolean;
}

// Security Item
export interface SecurityItem {
  category: string;
  status: "secure" | "warning" | "critical" | "info";
  description: string;
  recommendations?: string[];
}

// Anomaly Item
export interface AnomalyItem {
  id: string;
  title: string;
  description: string;
  timestamp: string;
  severity: "low" | "medium" | "high" | "critical";
  category: "system" | "network" | "security" | "application";
  affected: string;
  status: "new" | "investigating" | "mitigated" | "resolved";
  details?: string;
}

// System Telemetry Data
export interface SystemTelemetryData {
  systemOverview: SystemOverviewItem[];
  cpuHistory: DataPoint[];
  memoryHistory: DataPoint[];
  diskIO: DiskIOData;
  networkIO: NetworkIOData;
  processes: ProcessItem[];
  networkConnections: NetworkConnection[];
  networkInterfaces: NetworkInterface[];
  securityOverview: SecurityOverview;
  anomalies: AnomalyItem[];
  cpuDetails: CPUDetails;
  memoryDetails: MemoryDetails;
}


export const useTelemetrySocket = () => {
  
  const { mockSystemTelemetryData, 
    enrichTelemetryWithThreatData} = useTelemetryData();
  // Singleton socket instance
  let socket: Socket | null = null;
  let useOfflineMode = false; // Set default to offline mode to prevent connection errors
  let connectionAttempts = 0;
  const MAX_RECONNECTION_ATTEMPTS = 3;

  /**
   * Switch to offline mode with mock data
   */
  const  enableOfflineMode = () => {
    useOfflineMode = true;
    if (socket) {
      socket.disconnect();
      socket = null;
    }
    // toast.info("Switched to offline mode", {
    //   description: "Using enhanced threat detection with mock data"
    // });
  }

  /**
   * Switch back to online mode
   */
  const disableOfflineMode = () => {
    useOfflineMode = false;
    connectionAttempts = 0;
    toast.info("Switched to online mode", {
      description: "Attempting to connect to monitoring server"
    });
    return getSocket();
  }

  /**
   * Get mock telemetry data for offline mode with threat detection
   */
  const getMockTelemetryData = (): SystemTelemetryData =>{
    // Add threat detection to the mock data
    return enrichTelemetryWithThreatData(mockSystemTelemetryData);
  }

  /**
   * Check if system is in offline mode
   */
  const isOfflineMode = (): boolean =>{
    return useOfflineMode;
  }

  // Get the socket instance
  const getSocket = (): Socket =>{
    if (useOfflineMode) {
      // Don't try to connect in offline mode
      if (socket) {
        socket.disconnect();
        socket = null;
      }
      return null as unknown as Socket; // This is OK because we check isOfflineMode() before using
    }

    if (!socket) {
      // In a real app, this would connect to your server
      // https://ecyber-backend.onrender.com
      socket = io("http://127.0.0.1:8000",{
        autoConnect: true,
        reconnection: true,
        reconnectionAttempts: MAX_RECONNECTION_ATTEMPTS,
        reconnectionDelay: 1000,
        timeout: 5000, // Reduce timeout to fail faster
        transports: ['websocket'], // Prefer websockets for faster connections
      });

      socket.on('connect', () => {
        connectionAttempts = 0;
        toast.success('Connected to monitoring system', {
          id: 'socket-connection',
        });
      });

      // socket.on('connect_error', (err) => {
      //   connectionAttempts++;
        
      //   if (connectionAttempts >= MAX_RECONNECTION_ATTEMPTS) {
      //     toast.error(`Connection failed after ${MAX_RECONNECTION_ATTEMPTS} attempts. Switching to offline mode.`, {
      //       id: 'socket-error',
      //       duration: 5000,
      //     });
      //     enableOfflineMode();
      //   } else {
      //     // Only show error for last attempt
      //     if (connectionAttempts === MAX_RECONNECTION_ATTEMPTS - 1) {
      //       toast.error(`Connection error: ${err.message}. Retrying...`, {
      //         id: 'socket-error',
      //       });
      //     }
      //   }
      // });

      socket.on('disconnect', (reason) => {
        if (!useOfflineMode) {
          toast.error(`Disconnected: ${reason}. Attempting to reconnect...`, {
            id: 'socket-disconnect',
          });
        }
      });
    }

    return socket;
  }

  // Disconnect the socket
  const disconnectSocket = () =>{
    if (socket) {
      socket.disconnect();
      socket = null;
    }
  }

  // Enhanced threat detection capabilities
  const threatDetectionService = {
    // Analyze a process to determine if it's suspicious
    analyzeProcess: (process: ProcessItem): { suspicious: boolean; reasons: string[] } => {
      const reasons: string[] = [];
      
      // Check for unsigned system processes
      if (process.user.includes("SYSTEM") && process.signed === false) {
        reasons.push("Unsigned system process");
      }
      
      // Check for high resource usage
      if (process.cpu > 80) {
        reasons.push("Abnormally high CPU usage");
      }
      
      if (process.memory > 50) {
        reasons.push("Abnormally high memory usage");
      }
      
      // Check for suspicious process names (simplified example)
      const suspiciousNames = ["cryptominer", "exploit", "backdoor", "rootkit"];
      if (suspiciousNames.some(name => process.name.toLowerCase().includes(name))) {
        reasons.push("Suspicious process name");
      }
      
      return {
        suspicious: reasons.length > 0,
        reasons
      };
    },
    
    // Analyze network connection for suspicious activity
    analyzeConnection: (connection: NetworkConnection): { suspicious: boolean; reasons: string[] } => {
      const reasons: string[] = [];
      
      // Check for connections to known suspicious ports
      const suspiciousPorts = [4444, 1337, 31337, 8545, 3389];
      const remotePort = parseInt(connection.remoteAddress.split(":")[1]);
      
      if (suspiciousPorts.includes(remotePort)) {
        reasons.push(`Connection to suspicious port ${remotePort}`);
      }
      
      // Check for non-standard processes making network connections
      const normalNetworkProcesses = ["chrome.exe", "firefox.exe", "edge.exe", "outlook.exe"];
      if (!normalNetworkProcesses.includes(connection.process) && !connection.isInternal) {
        reasons.push("Unusual process making external connection");
      }
      
      return {
        suspicious: reasons.length > 0,
        reasons
      };
    },
    
    // Generate security recommendations based on current system state
    generateSecurityRecommendations: (data: SystemTelemetryData): SecurityItem[] => {
      const recommendations: SecurityItem[] = [];
      
      // Memory usage recommendations
      if (data?.memoryDetails?.percent > 85) {
        recommendations.push({
          category: "System Resources",
          status: "critical",
          description: "Memory usage critically high",
          recommendations: [
            "Close memory-intensive applications",
            "Check for memory leaks",
            "Consider increasing system memory"
          ]
        });
      }
      
      // Check for unsigned processes
      const unsignedProcesses = data.processes.filter(p => p.signed === false);
      if (unsignedProcesses.length > 0) {
        recommendations.push({
          category: "Security",
          status: "warning",
          description: `${unsignedProcesses.length} unsigned processes running`,
          recommendations: [
            "Verify the authenticity of these applications",
            "Consider replacing with signed alternatives",
            "Monitor these processes closely"
          ]
        });
      }
      
      // Network recommendations
      if (data.networkConnections.some(c => c.suspicious)) {
        recommendations.push({
          category: "Network",
          status: "critical",
          description: "Suspicious network connections detected",
          recommendations: [
            "Investigate the connections immediately",
            "Consider blocking remote IP addresses",
            "Monitor network traffic for data exfiltration"
          ]
        });
      }
      
      return recommendations;
    }
  };

  return {
    enableOfflineMode,
    disableOfflineMode,
    getMockTelemetryData,
    isOfflineMode,
    getSocket,
    disconnectSocket,
    threatDetectionService
  }
}