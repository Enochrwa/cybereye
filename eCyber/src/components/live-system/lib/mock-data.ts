import { 
  SystemTelemetryData, 
  DataPoint, 
  NetworkInterface,
  ProcessItem,
  NetworkConnection,
  AnomalyItem
} from './socket';

import { RootState } from '@/app/store';
import { useSelector } from 'react-redux';


export const useTelemetryData = () => {
  

  // const telemetry = useSelector((state: RootState) => state.socket.systemTelemetry);

  // if (telemetry.length > 0) {
  //   console.log("Telemetry Data: ", telemetry);
  // }

  // Generate CPU history data based on current CPU usage
  const generateCpuHistory = (currentUsage: number): DataPoint[] => {
    const now = Date.now();
    const data: DataPoint[] = [];
    
    // Start with the current usage and add some variation
    let baseValue = currentUsage;
    
    for (let i = 0; i < 100; i++) {
      // Add some random fluctuation to make the graph look realistic
      const variation = Math.random() * 10 - 5; // -5 to +5
      let value = baseValue + variation;
      
      // Keep within 0-100 range
      value = Math.max(0, Math.min(100, value));
      
      data.push({
        timestamp: now - (100 - i) * 1000,
        value: value
      });
      
      // Slightly adjust the base value for the next point (trend)
      baseValue = baseValue + (Math.random() * 2 - 1); // -1 to +1
      baseValue = Math.max(0, Math.min(100, baseValue));
    }
    
    return data;
  };

  // Generate memory history data based on current memory usage
  const generateMemoryHistory = (currentUsage: number): DataPoint[] => {
    const now = Date.now();
    const data: DataPoint[] = [];
    
    // Start with the current usage and add some variation
    let baseValue = currentUsage;
    
    for (let i = 0; i < 100; i++) {
      // Add some random fluctuation to make the graph look realistic
      const variation = Math.random() * 4 - 2; // -2 to +2
      let value = baseValue + variation;
      
      // Keep within 0-100 range
      value = Math.max(0, Math.min(100, value));
      
      data.push({
        timestamp: now - (100 - i) * 1000,
        value: value
      });
      
      // Slightly adjust the base value for the next point (trend)
      baseValue = baseValue + (Math.random() * 1 - 0.5); // -0.5 to +0.5
      baseValue = Math.max(0, Math.min(100, baseValue));
    }
    
    return data;
  };

  // Format network connections from the provided data
  const formatNetworkConnections = (): NetworkConnection[] => {
    return [
      {
        localAddress: "192.168.43.15:53135",
        remoteAddress: "172.16.0.1:8080",
        status: "ESTABLISHED",
        pid: 15732,
        process: "chrome.exe",
        suspicious: false,
        isInternal: true
      },
      {
        localAddress: "127.0.0.1:53111",
        remoteAddress: "127.0.0.1:53112",
        status: "ESTABLISHED",
        pid: 19164,
        process: "node.exe",
        suspicious: false,
        isInternal: true
      },
      {
        localAddress: "192.168.43.15:53189",
        remoteAddress: "172.16.0.1:8080",
        status: "ESTABLISHED",
        pid: 15732,
        process: "chrome.exe",
        suspicious: false,
        isInternal: true
      },
      {
        localAddress: "192.168.43.15:53175",
        remoteAddress: "172.16.0.1:8080",
        status: "ESTABLISHED",
        pid: 15732,
        process: "chrome.exe",
        suspicious: false,
        isInternal: true
      },
      {
        localAddress: "127.0.0.1:33045",
        remoteAddress: "127.0.0.1:33046",
        status: "ESTABLISHED",
        pid: 13456,
        process: "vscode.exe",
        suspicious: false,
        isInternal: true
      },
      {
        localAddress: "192.168.43.15:51933",
        remoteAddress: "172.16.0.1:8080",
        status: "ESTABLISHED",
        pid: 15732,
        process: "chrome.exe",
        suspicious: false,
        isInternal: true
      },
      {
        localAddress: "192.168.43.15:53194",
        remoteAddress: "172.16.0.1:8080",
        status: "ESTABLISHED",
        pid: 15732,
        process: "chrome.exe",
        suspicious: false,
        isInternal: true
      },
      {
        localAddress: "192.168.43.15:53225",
        remoteAddress: "104.18.23.192:443",
        status: "ESTABLISHED",
        pid: 15732,
        process: "chrome.exe",
        suspicious: true,
        isInternal: false
      },
      {
        localAddress: "192.168.43.15:53121",
        remoteAddress: "172.16.0.1:8080",
        status: "ESTABLISHED",
        pid: 15732,
        process: "chrome.exe",
        suspicious: false,
        isInternal: true
      },
      {
        localAddress: "192.168.43.15:52605",
        remoteAddress: "172.16.0.1:8080",
        status: "ESTABLISHED",
        pid: 15732,
        process: "chrome.exe",
        suspicious: false,
        isInternal: true
      }
    ];
  };

  // Format network interfaces from the provided data
  const formatNetworkInterfaces = (): NetworkInterface[] => {
    return [
      {
        name: "Ethernet",
        ipAddress: "169.254.157.112",
        macAddress: "C0-18-03-4A-86-46",
        speed: 0,
        is_up: false,
        status: "down",
        addresses: [
          {
            family: "AF_LINK",
            address: "C0-18-03-4A-86-46",
            netmask: null
          },
          {
            family: "AF_INET",
            address: "169.254.157.112",
            netmask: "255.255.0.0"
          }
        ],
        stats: {
          bytes_sent: 0,
          bytes_recv: 0,
          packets_sent: 0,
          packets_recv: 0
        }
      },
      {
        name: "vEthernet (WSL)",
        ipAddress: "172.27.16.1",
        macAddress: "00-15-5D-BB-D1-DB",
        speed: 4294,
        is_up: true,
        status: "up",
        addresses: [
          {
            family: "AF_LINK",
            address: "00-15-5D-BB-D1-DB",
            netmask: null
          },
          {
            family: "AF_INET",
            address: "172.27.16.1",
            netmask: "255.255.240.0"
          },
          {
            family: "AF_INET6",
            address: "fe80::7e1a:d970:45af:b963",
            netmask: null
          }
        ],
        stats: {
          bytes_sent: 14524378,
          bytes_recv: 32717164,
          packets_sent: 43649,
          packets_recv: 55926
        }
      }
    ];
  };

  // Format processes from the provided data
  const formatProcesses = (): ProcessItem[] => {
    return [
      {
        pid: 0,
        name: "System Idle Process",
        user: "NT AUTHORITY\\SYSTEM",
        cpu: 166.4,
        memory: 0.0001,
        status: "running",
        signed: null,
        suspicious: false
      },
      {
        pid: 14832,
        name: "chrome.exe",
        user: "ENOCK\\PC",
        cpu: 51.5,
        memory: 2.63,
        status: "running",
        signed: true,
        suspicious: false
      },
      {
        pid: 15732,
        name: "firefox.exe",
        user: "ENOCK\\PC",
        cpu: 38.2,
        memory: 1.87,
        status: "running",
        signed: true,
        suspicious: false
      },
      {
        pid: 13456,
        name: "vscode.exe",
        user: "ENOCK\\PC",
        cpu: 12.7,
        memory: 1.43,
        status: "running",
        signed: true,
        suspicious: false
      },
      {
        pid: 19164,
        name: "node.exe",
        user: "ENOCK\\PC",
        cpu: 8.3,
        memory: 0.95,
        status: "running",
        signed: true,
        suspicious: false
      },
      {
        pid: 4892,
        name: "svchost.exe",
        user: "NT AUTHORITY\\SYSTEM",
        cpu: 3.6,
        memory: 0.72,
        status: "running",
        signed: true,
        suspicious: false
      },
      {
        pid: 6728,
        name: "explorer.exe",
        user: "ENOCK\\PC",
        cpu: 1.2,
        memory: 0.87,
        status: "running",
        signed: true,
        suspicious: false
      }
    ];
  };

  // Generate disk I/O data for visualization
  const generateDiskIO = () => {
    return {
      read: [5.2, 4.7, 6.1, 8.3, 7.8, 5.6, 6.3, 7.1, 5.9, 6.5],
      write: [2.8, 3.4, 4.2, 3.9, 2.5, 3.7, 4.8, 3.6, 2.9, 3.3],
      timestamps: [
        "13:12", "13:13", "13:14", "13:15", "13:16", 
        "13:17", "13:18", "13:19", "13:20", "13:21"
      ]
    };
  };

  // Generate anomalies based on system data
  const generateAnomalies = (cpuUsage: number, memoryUsage: number): AnomalyItem[] => {
    const anomalies: AnomalyItem[] = [];
    
    // Add memory anomaly if usage is very high
    if (memoryUsage > 85) {
      anomalies.push({
        id: "anom-001",
        title: "High Memory Usage",
        description: `Memory usage at ${memoryUsage.toFixed(1)}% which is critically high`,
        timestamp: new Date().toISOString(),
        severity: "high",
        category: "system",
        affected: "System Memory",
        status: "new",
        details: "Consider closing memory-intensive applications or restarting the system"
      });
    }
    
    // Add CPU anomaly if usage is high
    if (cpuUsage > 80) {
      anomalies.push({
        id: "anom-002",
        title: "High CPU Usage",
        description: `CPU usage at ${cpuUsage.toFixed(1)}% which is significantly high`,
        timestamp: new Date().toISOString(),
        severity: "medium",
        category: "system",
        affected: "System CPU",
        status: "new",
        details: "Identify and close CPU-intensive applications"
      });
    }
    
    return anomalies;
  };

  // Mock system telemetry data based on real system information
  const mockSystemTelemetryData: SystemTelemetryData = {
    systemOverview: [
      {
        title: "CPU Usage",
        value: "48.4%",
        color: "var(--chart-purple)",
        icon: "cpu",
        details: "2 physical cores, 4 logical cores"
      },
      {
        title: "Memory Usage",
        value: "86.5%",
        color: "var(--chart-red)",
        icon: "memory",
        details: "7.2 GB used of 8.4 GB"
      },
      {
        title: "Disk Usage",
        value: "39.2%",
        color: "var(--chart-green)",
        icon: "disk",
        details: "391.6 GB used of 999.5 GB"
      },
      {
        title: "Network",
        value: "32.7 MB recv",
        color: "var(--chart-yellow)",
        icon: "network",
        details: "14.5 MB sent, 32.7 MB received"
      },
      {
        title: "System Uptime",
        value: "12h 45m",
        color: "var(--chart-blue)",
        icon: "clock"
      }
    ],
    cpuHistory: generateCpuHistory(48.4),
    memoryHistory: generateMemoryHistory(86.5),
    diskIO: generateDiskIO(),
    networkIO: {
      timestamp: Date.now(),
      sent: 14524378,
      received: 32717164
    },
    processes: formatProcesses(),
    networkConnections: formatNetworkConnections(),
    networkInterfaces: formatNetworkInterfaces(),
    securityOverview: {
      firewall: "Enabled",
      suspiciousConnections: 1,
      suspiciousProcesses: 0,
      systemUpdates: "Enabled"
    },
    anomalies: generateAnomalies(48.4, 86.5),
    cpuDetails: {
      cores: {
        physical: 2,
        logical: 4
      },
      frequency: {
        current: 1190,
        min: 0,
        max: 1190
      },
      usage: 48.4,
      times: {
        user: 20.1,
        system: 17.7,
        idle: 52.7,
        interrupt: 4.2,
        dpc: 5.3
      }
    },
    memoryDetails: {
      total: 8361132032,
      used: 7231762432,
      available: 1129369600,
      percent: 86.5,
      swap: {
        total: 8810938368,
        used: 1186111488,
        percent: 13.5
      }
    }
  };

  // Add more sophisticated threat detection functions
  const detectThreats = (data: SystemTelemetryData): AnomalyItem[] => {
    const threats: AnomalyItem[] = [];
    
    // Check for memory exhaustion
    if (data.memoryDetails.percent > 90) {
      threats.push({
        id: "threat-001",
        title: "Memory Exhaustion Risk",
        description: "System memory usage is critically high, potential DoS condition",
        timestamp: new Date().toISOString(),
        severity: "high",
        category: "security",
        affected: "System Memory",
        status: "new",
        details: "Possible memory leak or resource exhaustion attack"
      });
    }
    
    // Check for suspicious network activity
    const suspiciousConnections = data.networkConnections.filter(conn => conn.suspicious);
    if (suspiciousConnections.length > 0) {
      threats.push({
        id: "threat-002",
        title: "Suspicious Network Activity",
        description: `Detected ${suspiciousConnections.length} suspicious network connections`,
        timestamp: new Date().toISOString(),
        severity: "high",
        category: "network",
        affected: "Network Security",
        status: "investigating",
        details: "Possible command & control or data exfiltration attempt"
      });
    }
    
    // Check for high CPU usage by system processes
    const highCpuSystemProcesses = data.processes.filter(
      proc => proc.user.includes("SYSTEM") && proc.cpu > 50 && proc.name !== "System Idle Process"
    );
    
    if (highCpuSystemProcesses.length > 0) {
      threats.push({
        id: "threat-003",
        title: "System Process CPU Spike",
        description: "Unusual CPU activity from system processes",
        timestamp: new Date().toISOString(),
        severity: "medium",
        category: "system",
        affected: "System CPU",
        status: "new",
        details: "Potential cryptomining or privilege escalation attempt"
      });
    }
    
    return threats;
  };

  // Function to enrich the real-time data with threat detection
  const enrichTelemetryWithThreatData = (data: SystemTelemetryData): SystemTelemetryData => {
    // Detect threats based on the data
    const detectedThreats = detectThreats(data);
    
    // Add any detected threats to the anomalies list
    const enrichedData = {
      ...data,
      anomalies: [...data.anomalies, ...detectedThreats],
      securityOverview: {
        ...data.securityOverview,
        suspiciousConnections: data.networkConnections.filter(conn => conn.suspicious).length
      }
    };
    
    return enrichedData;
  };

  return {
    mockSystemTelemetryData,
    detectThreats,
    enrichTelemetryWithThreatData,
  }
}