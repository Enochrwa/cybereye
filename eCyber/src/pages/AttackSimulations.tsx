import React, { useEffect, useState } from 'react';
import { Socket } from 'socket.io-client';
import { useTheme } from '@/components/theme/ThemeProvider';

// Define AlertData interface - Copied from GenericAttackCard to ensure consistency
interface AlertData {
  id: string;
  timestamp: string;
  severity: string;
  source_ip: string;
  destination_ip: string;
  destination_port: number;
  protocol: string;
  description: string;
  threat_type: string;
  rule_id?: string;
  metadata?: any;
  anomaly_score?: number;
  threshold?: number;
  is_anomaly?: number;
}

// Interface for Firewall Block events
interface FirewallAlertData {
  id: string;
  timestamp: string;
  ip_address: string;
  reason: string;
  duration_seconds: number;
  source_component: string;
  packet_info?: {
    dst_ip?: string;
    protocol?: string;
  };
  action_taken: string;
}

import { 
  Shield, AlertTriangle, Network, Database, User, 
  Package, Globe, Terminal, Monitor 
} from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"; // Keep for other tabs if needed
// import { Button } from "@/components/ui/button"; // No longer explicitly used here, can be removed if not used by other child components
import { Separator } from "@/components/ui/separator";

// Import GenericAttackCard
import GenericAttackCard from '@/components/attack-simulations/GenericAttackCard';

// Import other simulation components that are not replaced by GenericAttackCard
import NetworkTrafficVisualizer from '@/components/attack-simulations/NetworkTrafficVisualizer';
// import ManualScanComponent from '@/components/attack-simulations/ManualScanComponent'; // Example if kept
// import HoneypotsInterface from '@/components/attack-simulations/HoneypotsInterface'; // Example if kept
import UserEducationCenter from '@/components/attack-simulations/UserEducationCenter';
// import PrivacyPolicy from '@/components/attack-simulations/PrivacyPolicy'; // Example if kept
// import ContactSupport from '@/components/attack-simulations/ContactSupport'; // Example if kept
import SystemMonitoring from '@/components/attack-simulations/SystemMonitoring';
// import DomainMonitor from '@/components/attack-simulations/DomainMonitor'; // Example if kept
// import VulnerabilityScanner from '@/components/attack-simulations/VulnerabilityScanner'; // Example if kept
// import URLClassifier from '@/components/attack-simulations/URLClassifier'; // Example if kept

import { useTelemetrySocket } from '@/components/live-system/lib/socket';

const classifierModels = [
  { id: "Bot", name: "Bot Activity", socketEventName: "BOT_ALERT", icon: <Package size={20} /> },
  { id: "Brute_Force", name: "Brute Force", socketEventName: "BRUTE_FORCE_ALERT", icon: <Terminal size={20} /> },
  { id: "DDoS", name: "DDoS Attack", socketEventName: "DDOS_ALERT", icon: <Shield size={20} /> },
  { id: "DoS", name: "DoS Attack", socketEventName: "DOS_ALERT", icon: <AlertTriangle size={20} /> },
  { id: "Heartbleed", name: "Heartbleed Exploit", socketEventName: "HEARTBLEED_ALERT", icon: <Database size={20} /> }, // Example icon
  { id: "Infiltration", name: "Infiltration Attempt", socketEventName: "INFILTRATION_ALERT", icon: <User size={20} /> }, // Example icon
  { id: "Port_Scan", name: "Port Scanning", socketEventName: "PORT_SCAN_ALERT", icon: <Network size={20} /> },
  { id: "Web_Attack", name: "Web Attack", socketEventName: "WEB_ATTACK_ALERT", icon: <Globe size={20} /> } // Example icon for Web Attack
];

const AttackSimulations = () => {
  const { getSocket } = useTelemetrySocket();
  const { theme } = useTheme(); // Keep if used for styling decisions not handled by CSS vars
  const [activeTab, setActiveTab] = useState("attack-simulations");
  const socket: Socket | null = getSocket();

  // State for alerts
  const [alerts, setAlerts] = useState<Record<string, AlertData[]>>({
    // Initialize states for all classifier models
    Bot: [],
    Brute_Force: [],
    DDoS: [],
    DoS: [],
    Heartbleed: [],
    Infiltration: [],
    Port_Scan: [],
    Web_Attack: [],
    // Keep other states as needed
    SQL_Injection: [], // Will be removed if SQLInjectionSimulation is fully replaced and not a separate event
    Anomaly: [],
    Firewall: []
  });

  useEffect(() => {
    if (socket) {
      socket.on('interfaces', (data: any) => {
        console.log("Network Interfaces: ", data);
      });

      const eventListeners: { eventName: string, handler: (data: any) => void }[] = [];

      // Iterate over classifierModels to register socket listeners
      classifierModels.forEach(model => {
        const handler = (data: AlertData) => {
          console.log(`Received ${model.socketEventName}:`, data);
          setAlerts(prevAlerts => ({
            ...prevAlerts,
            [model.id]: [data, ...(prevAlerts[model.id] || [])].slice(0, 20)
          }));
        };
        socket.on(model.socketEventName, handler);
        eventListeners.push({ eventName: model.socketEventName, handler });
      });
      
      // SQL_Injection specific listener - if it's a distinct event and not covered by Web_Attack
      // If SQL_Injection alerts are sent via WEB_ATTACK_ALERT, this specific listener might be redundant
      // or SQL_Injection key in `alerts` state should be populated by WEB_ATTACK_ALERT handler if needed.
      // For now, assuming it might be a separate event or handled by an old component.
      // If SQLInjectionSimulation component is removed, this might need adjustment.
      const sqlInjectionEventHandler = (data: AlertData) => {
        console.log(`Received SQL_INJECTION_ALERT:`, data);
        setAlerts(prevAlerts => ({
            ...prevAlerts,
            SQL_Injection: [data, ...(prevAlerts.SQL_Injection || [])].slice(0, 20)
        }));
      };
      socket.on("SQL_INJECTION_ALERT", sqlInjectionEventHandler);
      eventListeners.push({ eventName: "SQL_INJECTION_ALERT", handler: sqlInjectionEventHandler});


      // Listener for Anomaly Alerts
      const anomalyEventName = "ANOMALY_ALERT";
      const anomalyHandler = (data: AlertData) => {
        console.log(`Received ${anomalyEventName}:`, data);
        setAlerts(prevAlerts => ({
          ...prevAlerts,
          Anomaly: [data, ...(prevAlerts.Anomaly || [])].slice(0, 20)
        }));
      };
      socket.on(anomalyEventName, anomalyHandler);
      eventListeners.push({ eventName: anomalyEventName, handler: anomalyHandler });

      // Listener for Firewall Blocked events
      const firewallEventName = "firewall_blocked";
      const firewallHandler = (data: FirewallAlertData) => {
        console.log(`Received ${firewallEventName}:`, data);
        const mappedAlert: AlertData = {
          id: data.id,
          timestamp: data.timestamp,
          severity: "High",
          source_ip: data.ip_address,
          destination_ip: data.packet_info?.dst_ip || "N/A",
          destination_port: 0,
          protocol: data.packet_info?.protocol || "N/A",
          description: data.reason,
          threat_type: "Firewall Block",
          rule_id: data.source_component,
          metadata: {
            duration_seconds: data.duration_seconds,
            action_taken: data.action_taken,
            original_packet_info: data.packet_info,
            source_component: data.source_component,
          }
        };
        setAlerts(prevAlerts => ({
          ...prevAlerts,
          Firewall: [mappedAlert, ...(prevAlerts.Firewall || [])].slice(0, 20)
        }));
      };
      socket.on(firewallEventName, firewallHandler);
      eventListeners.push({ eventName: firewallEventName, handler: firewallHandler as any });

      return () => {
        socket.off('interfaces');
        eventListeners.forEach(({ eventName, handler }) => {
          socket.off(eventName, handler);
        });
      };
    }
  }, [socket]);

  return (
    <div className="container mx-auto py-8 animate-fade-in">
      <header className="mb-8">
        <h1 className="text-3xl font-bold text-isimbi-purple mb-2">
          Attacks Playground
        </h1>
        <p className="text-muted-foreground">
          Interactive security testing environment for simulating various cyber attacks and monitoring system responses
        </p>
        <Separator className="my-4" />
      </header>
      
      <Tabs defaultValue="attack-simulations" className="w-full" onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 lg:grid-cols-8 mb-8"> {/* Adjusted grid for more tabs */}
          <TabsTrigger value="attack-simulations" className="gap-2">
            <Shield size={16} />
            <span className="hidden md:inline">Attacks</span>
          </TabsTrigger>
          <TabsTrigger value="network">
            <Network size={16} />
            <span className="hidden md:inline">Network</span>
          </TabsTrigger>
          <TabsTrigger value="system">
            <Monitor size={16} />
            <span className="hidden md:inline">System</span>
          </TabsTrigger>
          {/* <TabsTrigger value="education">
            <User size={16} />
            <span className="hidden md:inline">Education</span>
          </TabsTrigger> */}
          {/* Add other tabs back if needed */}
        </TabsList>
        
        <TabsContent value="attack-simulations" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {classifierModels.map(model => (
              <GenericAttackCard
                key={model.id}
                attackName={model.name}
                alerts={alerts[model.id] || []}
                icon={model.icon || <Shield size={20} />} // Use model specific icon or fallback
              />
            ))}
            {/* SQLInjectionSimulation is removed as per instruction to use GenericAttackCard for 8 models.
                If SQL_Injection is a 9th distinct model and its alerts are via SQL_INJECTION_ALERT,
                it should be added to classifierModels array. Otherwise, alerts.SQL_Injection state
                will not be populated by the new GenericAttackCards.
                For now, assuming Web_Attack might cover SQL Injections or it's handled differently.
            */}
            {/* <SQLInjectionSimulation alerts={alerts.SQL_Injection || []} /> */}

            {/* Other specific simulations that don't fit GenericAttackCard can be added here
                For example, PhishingSimulation, MalwareSimulation etc. if they have unique UI beyond alerts.
                For this task, these were removed.
            */}
            {/* <PhishingSimulation /> */}
            {/* <UnauthorizedAccessSimulation /> */}
            {/* <MalwareSimulation /> */}
            {/* <DataExfiltrationSimulation /> */}
            {/* <BehavioralDeviationSimulation /> */}
          </div>
        </TabsContent>
        
        <TabsContent value="network">
          <NetworkTrafficVisualizer />
        </TabsContent>
        
        <TabsContent value="system">
          <SystemMonitoring anomalyAlerts={alerts.Anomaly || []} firewallAlerts={alerts.Firewall || []} />
        </TabsContent>
        
        {/* <TabsContent value="education">
          <UserEducationCenter />
        </TabsContent> */}
        
        {/* Other TabsContent sections */}
      </Tabs>
    </div>
  );
};

export default AttackSimulations;