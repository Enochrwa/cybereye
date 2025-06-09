
import React, { useState, useEffect } from 'react';
import { Search, Filter, Download, RefreshCw, AlertTriangle, Shield, Activity, FileText, Check, StopCircle, Eye } from 'lucide-react';
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardContent, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import Header from '../components/layout/Header';
import { useToast } from "@/hooks/use-toast";

import { FirewallLog, NetworkEventLog, ThreatLog, SystemLog, MonitoringLog, FirewallRule, IDSRule } from '@/types';

// Import our custom log table components
import FirewallLogsTable from '@/components/logs/FirewallLogsTable';
import NetworkEventsTable from '@/components/logs/NetworkEventsTable';
import ThreatLogsTable from '@/components/logs/ThreatLogsTable';import { SystemLogsTable } from '@/components/logs/SystemLogsTable';
import MonitoringLogsTable from '@/components/logs/MonitoringLogsTable';
import RulesTable from '@/components/logs/RulesTable';

const sampleFirewallLogs: FirewallLog[] = [
  {
    id: 808,
    timestamp: "2025-05-13 16:57:05.218033",
    action: "ALLOW",
    source_ip: "37.186.19.224",
    destination_ip: "63.229.38.211",
    protocol: "TCP",
    rule_id: "MATCHED-2170"
  },
  {
    id: 809,
    timestamp: "2025-05-13 17:11:18.210111",
    action: "DENY",
    source_ip: "116.193.248.49",
    destination_ip: "96.33.116.102",
    protocol: "ICMP",
    rule_id: "MATCHED-6607"
  },
  {
    id: 810,
    timestamp: "2025-05-13 17:11:18.614888",
    action: "DENY",
    source_ip: "21.211.161.111",
    destination_ip: "176.97.114.222",
    protocol: "TCP",
    rule_id: "MATCHED-9736"
  },
  {
    id: 811,
    timestamp: "2025-05-13 17:11:19.103064",
    action: "ALLOW",
    source_ip: "64.227.38.115",
    destination_ip: "164.225.143.131",
    protocol: "UDP",
    rule_id: "MATCHED-2"
  },
  {
    id: 812,
    timestamp: "2025-05-13 17:11:19.280751",
    action: "DENY",
    source_ip: "86.199.138.90",
    destination_ip: "177.86.56.72",
    protocol: "UDP",
    rule_id: "MATCHED-7054"
  }
];

const sampleNetworkLogs: NetworkEventLog[] = [
  {
    id: 834,
    timestamp: "2025-05-13 17:59:48.087906",
    event_type: "http_request",
    source_ip: "220.100.151.125",
    source_mac: "90:60:32:37:38:e5",
    destination_ip: "218.161.74.242",
    destination_port: 37357,
    protocol: "TCP",
    length: 995,
    application: "DNS",
    payload: "Light that again start nor.",
    geo: {
      country: "Albania",
      city: "New Mariaburgh",
      isp: "Gregory-Moore"
    }
  },
  {
    id: 835,
    timestamp: "2025-05-13 17:59:49.976138",
    event_type: "http_request",
    source_ip: "200.46.220.177",
    source_mac: "5e:94:68:8c:62:d8",
    destination_ip: "151.198.0.106",
    destination_port: 38047,
    protocol: "ICMP",
    length: 193,
    application: "DNS",
    payload: "Majority energy key always professional some.",
    geo: {
      country: "China",
      city: "Amandamouth",
      isp: "Gates PLC"
    }
  },
  {
    id: 836,
    timestamp: "2025-05-13 17:59:52.470944",
    event_type: "dns_query",
    source_ip: "10.43.186.141",
    source_mac: "50:d6:93:0c:23:42",
    destination_ip: "138.107.116.81",
    destination_port: 10898,
    protocol: "TCP",
    length: 673,
    application: "HTTP",
    payload: "Might whole run Mrs staff nation push.",
    geo: {
      country: "Cambodia",
      city: "Lake Jennifer",
      isp: "Ford, Ferguson and Zhang"
    }
  }
];

const sampleThreatLogs: ThreatLog[] = [
  {
    id: 834,
    timestamp: "2025-05-13 17:59:48.087906",
    event_type: "http_request",
    src_ip: "220.100.151.125",
    src_mac: "90:60:32:37:38:e5",
    dest_ip: "218.161.74.242",
    port: 37357,
    protocol: "TCP",
    packet_size: 995,
    service: "DNS",
    message: "Light that again start nor.",
    geo: {
      country: "Albania",
      city: "New Mariaburgh",
      isp: "Gregory-Moore"
    }
  },
  {
    id: 835,
    timestamp: "2025-05-13 17:59:49.976138",
    event_type: "http_request",
    src_ip: "200.46.220.177",
    src_mac: "5e:94:68:8c:62:d8",
    dest_ip: "151.198.0.106",
    port: 38047,
    protocol: "ICMP",
    packet_size: 193,
    service: "DNS",
    message: "Majority energy key always professional some.",
    geo: {
      country: "China",
      city: "Amandamouth",
      isp: "Gates PLC"
    }
  },
  {
    id: 836,
    timestamp: "2025-05-13 17:59:52.470944",
    event_type: "dns_query",
    src_ip: "10.43.186.141",
    src_mac: "50:d6:93:0c:23:42",
    dest_ip: "138.107.116.81",
    port: 10898,
    protocol: "TCP",
    packet_size: 673,
    service: "HTTP",
    message: "Might whole run Mrs staff nation push.",
    geo: {
      country: "Cambodia",
      city: "Lake Jennifer",
      isp: "Ford, Ferguson and Zhang"
    }
  },
  {
    id: 837,
    timestamp: "2025-05-13 17:59:54.523828",
    event_type: "http_request",
    src_ip: "19.150.0.145",
    src_mac: "76:fd:9f:db:64:6a",
    dest_ip: "177.245.39.189",
    port: 61193,
    protocol: "ICMP",
    packet_size: 242,
    service: "DNS",
    message: "Sing ago red group some order.",
    geo: {
      country: "Cameroon",
      city: "Dawnmouth",
      isp: "Fowler Ltd"
    }
  }
];

const sampleSystemLog: SystemLog = {
  id: 101,
  timestamp: "2025-05-13T18:30:45.123456+00:00",
  component: "auth",
  level: "error",
  message: "Failed login attempt for user ID 42",
  details: {
    method: "POST",
    endpoint: "/api/login",
    error_code: "INVALID_PASSWORD",
    attempts: 3
  },
  user_id: 42,
  source_ip: "192.168.1.10",
  request_id: "req_abc123xyz",
  resolved: false,
  resolution_notes: null,
  stack_trace: "Traceback (most recent call last):\n  File \"auth.py\", line 42, in login_user\n    raise InvalidPasswordError()\nInvalidPasswordError",
  duration_ms: 87
};

const sampleMonitoringLog: MonitoringLog = {
  id: 205,
  type: "SYSTEM",
  level: "WARNING",
  message: "High CPU usage detected",
  source: "monitoring_service",
  details: {
    cpu: 92.5,
    threshold: 90,
    host: "server-02",
    duration_sec: 15
  },
  timestamp: "2025-05-13T18:35:22.567890+00:00",
  action: "AlertRaised",
  user_id: 10,
  user: {
    id: 10,
    username: "admin_user",
    email: "admin@example.com"
  }
};

const sampleFirewallRule: FirewallRule = {
  id: 101,
  name: "Block Suspicious IP",
  action: "DENY",
  direction: "INBOUND",
  source_ip: "203.0.113.45",
  destination_ip: "10.0.0.15",
  source_port: 443,
  destination_port: 8080,
  protocol: "TCP",
  is_active: true,
  created_at: "2025-05-13T15:00:22.765000+00:00",
  updated_at: "2025-05-13T16:40:02.125000+00:00"
};

const sampleIDSRule: IDSRule = {
  id: 1,
  name: "Detect SSH Brute Force",
  description: "Trigger when multiple SSH login attempts are detected from the same IP within a short time window.",
  action: "ALERT",
  protocol: "TCP",
  source_ip: "192.168.1.0/24",
  source_port: "any",
  destination_ip: "10.0.0.15",
  destination_port: "22",
  pattern: "Failed password for",
  content_modifiers: {
    nocase: true,
    depth: 50,
    offset: 0
  },
  threshold: 5,
  window: 60,
  active: true,
  severity: "high",
  created_at: "2025-05-13T15:10:00.000000+00:00",
  updated_at: "2025-05-13T16:20:00.000000+00:00"
};

const Logs = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [firewallLogs, setFirewallLogs] = useState<FirewallLog[]>([]);
  const [networkLogs, setNetworkLogs] = useState<NetworkEventLog[]>([]);
  const [threatLogs, setThreatLogs] = useState<ThreatLog[]>([]);
  const [systemLogs, setSystemLogs] = useState<SystemLog[]>([]);
  const [monitoringLogs, setMonitoringLogs] = useState<MonitoringLog[]>([]);
  const [firewallRules, setFirewallRules] = useState<FirewallRule[]>([]);
  const [idsRules, setIDSRules] = useState<IDSRule[]>([]);
  const [activeTab, setActiveTab] = useState('firewall');
  const [isLoading, setIsLoading] = useState(false);
  const [selectedLog, setSelectedLog] = useState<any>(null);
  const [sourceFilter, setSourceFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const { toast } = useToast();
  
  // Initial load
  useEffect(() => {
    loadLogs();
  }, []);
  
  const loadLogs = () => {
    setIsLoading(true);
    
    // Simulate loading
    setTimeout(() => {
      // Load sample data
      setFirewallLogs(sampleFirewallLogs);
      setNetworkLogs(sampleNetworkLogs);
      setThreatLogs(sampleThreatLogs);
      setSystemLogs([sampleSystemLog]);
      setMonitoringLogs([sampleMonitoringLog]);
      setFirewallRules([sampleFirewallRule]);
      setIDSRules([sampleIDSRule]);
      
      setIsLoading(false);
      toast({
        title: "Logs Loaded",
        description: "Log data retrieved successfully"
      });
    }, 800);
  };
  
  const handleRefresh = () => {
    loadLogs();
  };

  const handleViewDetails = (log: any) => {
    setSelectedLog(log);
    toast({
      title: "Log Details",
      description: `Viewing details for log ID: ${log.id}`
    });
  };
  
  const handleExportLogs = () => {
    toast({
      title: "Logs Exported",
      description: "Log data exported successfully"
    });
  };
  
  return (
    <div className="flex-1 flex flex-col overflow-hidden">

      
      <main className="flex-1 overflow-auto p-6">
        <div className="max-w-7xl mx-auto">
          {/* Page header */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold tracking-tight">System Logs</h1>
              <p className="text-muted-foreground">Review and analyze system log events</p>
            </div>
            
            <div className="mt-4 md:mt-0 flex items-center space-x-2">
              <div className="relative">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search logs..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-8 w-[200px] md:w-[300px]"
                />
              </div>
              
              <Button variant="outline" size="icon" onClick={handleRefresh}>
                <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              </Button>
              
              <Button variant="outline" className="hidden sm:flex" onClick={handleExportLogs}>
                <Download className="mr-2 h-4 w-4" />
                Export
              </Button>
            </div>
          </div>
          
          {/* Logs content */}
          <Card className="bg-card shadow rounded-lg">
            <CardHeader className="pb-2">
              <Tabs value={activeTab} onValueChange={setActiveTab}>
                <TabsList className="grid grid-cols-3 md:grid-cols-6 w-full">
                  <TabsTrigger value="firewall" className="flex items-center gap-1">
                    <Shield className="h-4 w-4" />
                    <span className="hidden md:inline">Firewall</span>
                  </TabsTrigger>
                  <TabsTrigger value="network" className="flex items-center gap-1">
                    <Activity className="h-4 w-4" />
                    <span className="hidden md:inline">Network</span>
                  </TabsTrigger>
                  <TabsTrigger value="threats" className="flex items-center gap-1">
                    <AlertTriangle className="h-4 w-4" />
                    <span className="hidden md:inline">Threats</span>
                  </TabsTrigger>
                  <TabsTrigger value="system" className="flex items-center gap-1">
                    <FileText className="h-4 w-4" />
                    <span className="hidden md:inline">System</span>
                  </TabsTrigger>
                  <TabsTrigger value="monitoring" className="flex items-center gap-1">
                    <Activity className="h-4 w-4" />
                    <span className="hidden md:inline">Monitoring</span>
                  </TabsTrigger>
                  <TabsTrigger value="rules" className="flex items-center gap-1">
                    <Shield className="h-4 w-4" />
                    <span className="hidden md:inline">Rules</span>
                  </TabsTrigger>
                </TabsList>
                
                <CardContent className="pt-6 px-0">
                  <TabsContent value="firewall" className="m-0">
                    <FirewallLogsTable 
                      logs={firewallLogs}
                      onViewDetails={handleViewDetails}
                    />
                  </TabsContent>
                  
                  <TabsContent value="network" className="m-0">
                    <NetworkEventsTable 
                      logs={networkLogs}
                      onViewDetails={handleViewDetails}
                    />
                  </TabsContent>
                  
                  <TabsContent value="threats" className="m-0">
                    <ThreatLogsTable 
                      logs={threatLogs}
                      onViewDetails={handleViewDetails}
                    />
                  </TabsContent>
                  
                  <TabsContent value="system" className="m-0">
                    <SystemLogsTable 
                      logs={systemLogs}
                      onViewDetails={handleViewDetails}
                    />
                  </TabsContent>
                  
                  <TabsContent value="monitoring" className="m-0">
                    <MonitoringLogsTable 
                      logs={monitoringLogs}
                      onViewDetails={handleViewDetails}
                    />
                  </TabsContent>
                  
                  <TabsContent value="rules" className="m-0">
                    <RulesTable 
                      firewallRules={firewallRules}
                      idsRules={idsRules}
                      onEdit={(rule, type) => {
                        toast({
                          title: "Edit Rule",
                          description: `Editing ${type} rule: ${rule.name}`
                        });
                      }}
                      onDelete={(id, type) => {
                        toast({
                          title: "Delete Rule",
                          description: `Deleting ${type} rule: ID ${id}`
                        });
                      }}
                      onToggle={(id, active, type) => {
                        toast({
                          title: "Rule Status Changed",
                          description: `${type} rule ID ${id} is now ${active ? 'active' : 'inactive'}`
                        });
                      }}
                    />
                  </TabsContent>
                </CardContent>
              </Tabs>
            </CardHeader>
          </Card>
          
          {/* Stats Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mt-6">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center">
                  <Shield className="h-4 w-4 text-primary mr-2" />
                  Firewall Events
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{firewallLogs.length}</div>
                <p className="text-xs text-muted-foreground">Last 24 hours</p>
                <div className="flex items-center mt-2 text-sm">
                  <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 mr-2">
                    {firewallLogs.filter(log => log.action === "DENY").length} Blocked
                  </Badge>
                  <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30">
                    {firewallLogs.filter(log => log.action === "ALLOW").length} Allowed
                  </Badge>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center">
                  <Activity className="h-4 w-4 text-blue-500 mr-2" />
                  Network Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{networkLogs.length}</div>
                <p className="text-xs text-muted-foreground">Network events</p>
                <div className="flex items-center mt-2 text-sm">
                  <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/30 mr-2">
                    {networkLogs.filter(log => log.protocol === "TCP").length} TCP
                  </Badge>
                  <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/30">
                    {networkLogs.filter(log => log.protocol === "ICMP").length} ICMP
                  </Badge>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center">
                  <AlertTriangle className="h-4 w-4 text-red-500 mr-2" />
                  Threat Events
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{threatLogs.length}</div>
                <p className="text-xs text-muted-foreground">Detected threats</p>
                <div className="flex items-center mt-2 text-sm">
                  <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30">
                    {threatLogs.length} Threats Detected
                  </Badge>
                </div>
              </CardContent>
            </Card>
            
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium flex items-center">
                  <FileText className="h-4 w-4 text-purple-500 mr-2" />
                  System Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{systemLogs.length + monitoringLogs.length}</div>
                <p className="text-xs text-muted-foreground">System log entries</p>
                <div className="flex items-center mt-2 text-sm">
                  <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 mr-2">
                    {systemLogs.filter(log => log.level.toLowerCase() === 'error').length} Errors
                  </Badge>
                  <Badge variant="outline" className="bg-amber-500/10 text-amber-400 border-amber-500/30">
                    {monitoringLogs.filter(log => log.level === 'WARNING').length} Warnings
                  </Badge>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
};

export default Logs;