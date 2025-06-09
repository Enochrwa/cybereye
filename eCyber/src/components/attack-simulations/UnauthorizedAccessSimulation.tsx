import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { ShieldAlert, UserCog, KeyRound } from 'lucide-react'; // UserCog, KeyRound are examples, adjust as needed
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast"; // Keep for block/mitigate actions
import { Button } from "@/components/ui/button"; // For action buttons

interface AccessAlert {
  id: string;
  timestamp: string;
  source_ip?: string;
  description: string;
  severity: 'High' | 'Critical' | 'Medium' | 'Low' | string; // Allow string for flexibility
  type: string; // e.g., "ARP Spoofing", "SSH Brute Force", "Failed Login", "Malicious Connection"
  target_service?: string;
  username?: string;
  details?: string;
}

const UnauthorizedAccessSimulation = () => {
  const { toast } = useToast();
  const [accessAlerts, setAccessAlerts] = useState<AccessAlert[]>([]);

  useEffect(() => {
    const handleAccessAlert = (data: any) => {
      // Check if data.type indicates an access-related alert
      // This is a broad category, so type checking might need to be flexible
      const isAccessRelatedType = (type: string | undefined) => {
        if (!type) return false;
        const lowerType = type.toLowerCase();
        return lowerType.includes('arp spoof') ||
               lowerType.includes('brute force') ||
               lowerType.includes('failed login') ||
               lowerType.includes('unauthorized access') ||
               lowerType.includes('suspicious login') ||
               lowerType.includes('malicious connection'); // From malware.py
      };

      if (data && (isAccessRelatedType(data.type) || isAccessRelatedType(data.alert_type) || isAccessRelatedType(data.event_type))) {
        const newAlert: AccessAlert = {
          id: data.id || `access-alert-${Date.now()}-${Math.random()}`,
          timestamp: data.timestamp || new Date().toISOString(),
          source_ip: data.source_ip || data.src_ip || 'N/A',
          description: data.description || data.message || 'Suspicious access attempt detected.',
          severity: data.severity || 'Medium',
          type: data.type || data.alert_type || data.event_type || 'Access Anomaly',
          target_service: data.target_service || data.service || (data.destination_port ? `Port ${data.destination_port}` : undefined),
          username: data.username || undefined,
          details: data.details || (data.metadata ? JSON.stringify(data.metadata) : undefined),
        };
        setAccessAlerts(prev => [newAlert, ...prev.slice(0, 49)]); // Keep last 50
      }
    };

    // TODO: Replace with actual socket listeners
    // Example:
    // if (socket) {
    //   socket.on('security_alert', handleAccessAlert); // For alerts from sniffer (e.g., ARP, Brute Force)
    //   socket.on('malware_malicious_connection', handleAccessAlert); // For alerts relayed from malware.py
    // }
    // console.log("UnauthorizedAccessSimulation: Would listen for access-related socket events here.");

    // Mock data for subtask UI verification
    if (process.env.NODE_ENV === 'development' && !(window as any).__mockAccessAlertsAdded) {
      (window as any).__mockAccessAlertsAdded = true;
      setTimeout(() => {
        handleAccessAlert({
          id: 'mockaccess1', type: 'SSH Brute Force', timestamp: new Date().toISOString(),
          source_ip: '203.0.113.45', description: 'Multiple failed SSH login attempts.',
          severity: 'High', target_service: 'SSH (Port 22)', username: 'root'
        });
        setTimeout(() => {
          handleAccessAlert({
            id: 'mockaccess2', type: 'ARP Spoofing', timestamp: new Date().toISOString(),
            source_ip: '192.168.1.105', description: 'ARP spoofing detected, MAC 00:1A:2B:3C:4D:5E claims to be Gateway 192.168.1.1.',
            severity: 'Critical', details: "Original Gateway MAC: 00:AA:BB:CC:DD:EE"
          });
          handleAccessAlert({
            id: 'mockaccess3', event_type: 'Malicious Connection', timestamp: new Date().toISOString(),
            src_ip: '10.0.5.15', description: 'Connection to known C&C server.',
            severity: 'Critical', service: 'HTTPS (Port 443)', message: 'Outbound connection to malicious host evil.com'
          });
        }, 1500);
      }, 1000);
    }

    return () => {
      // TODO: Clean up socket listeners
      // delete (window as any).__mockAccessAlertsAdded;
    };
  }, []);
  
  const getSeverityBadge = (severity?: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical': return <Badge variant="destructive">Critical</Badge>;
      case 'high': return <Badge variant="destructive" className="bg-orange-500 hover:bg-orange-600">High</Badge>;
      case 'medium': return <Badge variant="outline" className="border-yellow-500 text-yellow-500">Medium</Badge>;
      case 'low': return <Badge variant="secondary">Low</Badge>;
      default: return <Badge variant="outline">{severity || 'Unknown'}</Badge>;
    }
  };

  return (
    <Card className="overflow-hidden shadow-lg border-red-500/20">
      <CardHeader className="bg-gradient-to-r from-red-700/20 via-red-900/10 to-transparent">
        <CardTitle className="flex items-center gap-2">
          <UserCog className="h-5 w-5 text-red-500" />
          Unauthorized Access Alerts
        </CardTitle>
        <CardDescription>
          Real-time monitoring of detected unauthorized access attempts and suspicious activities.
        </CardDescription>
      </CardHeader>

      <CardContent className="p-6">
        {accessAlerts.length === 0 ? (
          <div className="text-center text-muted-foreground py-8">
            <KeyRound size={48} className="mx-auto mb-2 opacity-30" />
            No unauthorized access alerts detected recently.
          </div>
        ) : (
          <ScrollArea className="h-[400px] border rounded-md">
            <div className="divide-y">
              {accessAlerts.map((alert) => (
                <div key={alert.id} className="p-3 hover:bg-muted/50">
                  <div className="flex justify-between items-start mb-1">
                    <h4 className="font-semibold text-sm">{alert.type}</h4>
                    {getSeverityBadge(alert.severity)}
                  </div>
                  <p className="text-xs text-muted-foreground mb-0.5">
                    {new Date(alert.timestamp).toLocaleString()}
                  </p>
                  <p className="text-sm mb-1">{alert.description}</p>
                  <div className="text-xs text-gray-500 space-x-2">
                    {alert.source_ip && <span>Source IP: <span className="font-mono">{alert.source_ip}</span></span>}
                    {alert.target_service && <span>Target: {alert.target_service}</span>}
                    {alert.username && <span>User: {alert.username}</span>}
                  </div>
                  {alert.details && <p className="text-xs text-gray-400 mt-1">Details: {alert.details}</p>}
                   <Button 
                      variant="outline" 
                      size="xs" 
                      className="mt-2 h-6 text-xs"
                      onClick={() => toast({ title: 'Action Taken', description: `Investigating alert ${alert.id.substring(0,12)} for ${alert.source_ip}`})}
                    >
                      Investigate
                    </Button>
                </div>
              ))}
            </div>
          </ScrollArea>
        )}
      </CardContent>
      <CardFooter className="bg-card/50 border-t border-border/50 py-3">
        <div className="text-xs text-muted-foreground">
          Monitoring for unauthorized access events...
        </div>
      </CardFooter>
    </Card>
  );
};

export default UnauthorizedAccessSimulation;
