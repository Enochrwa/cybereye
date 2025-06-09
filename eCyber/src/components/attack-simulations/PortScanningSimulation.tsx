import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Shield, Activity, AlertCircle } from 'lucide-react'; // AlertCircle might be unused
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area"; // Added ScrollArea
import { useToast } from "@/hooks/use-toast";

// Shared AlertData interface (can be moved to a shared types file)
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

interface PortScanningSimulationProps {
  alerts: AlertData[];
}

const PortScanningSimulation: React.FC<PortScanningSimulationProps> = ({ alerts }) => {
  const { toast } = useToast();
  // Removed internal state and useEffect for alerts, now passed via props

  return (
    <Card className="overflow-hidden shadow-lg border-orange-500/20">
      <CardHeader className="bg-gradient-to-r from-orange-500/10 to-transparent">
        <CardTitle className="flex items-center gap-2">
          <Activity className="h-5 w-5 text-orange-500" />
          Detected Port Scan Activity
        </CardTitle>
        <CardDescription>
          Real-time list of detected port scanning events against the network.
        </CardDescription>
      </CardHeader>

      <CardContent className="p-6">
        {alerts && alerts.length > 0 ? (
          <div className="border rounded-lg overflow-hidden">
            <div className="grid grid-cols-7 bg-muted p-2 text-xs font-medium gap-2">
              <div className="col-span-2">Timestamp</div>
              <div>Source IP</div>
              <div>Target IP</div>
              <div>Target Port</div>
              <div className="col-span-1">Description</div>
              <div>Severity</div>
              {/* Removed Actions for now, can be added back if needed */}
            </div>
            <ScrollArea className="h-[400px]">
              <div className="divide-y">
                {alerts.map((alert) => (
                  <div key={alert.id} className="grid grid-cols-7 p-2 text-sm items-center hover:bg-muted/50 gap-2">
                    <div className="col-span-2">{new Date(alert.timestamp).toLocaleString()}</div>
                    <div className="font-mono break-all">{alert.source_ip}</div>
                    <div className="font-mono break-all">{alert.destination_ip}</div>
                    <div className="font-mono break-all">{alert.destination_port}</div>
                    <div className="break-words col-span-1 text-xs">{alert.description}</div>
                    <div>
                      <Badge variant={
                        alert.severity.toLowerCase() === 'critical' ? 'destructive' :
                        alert.severity.toLowerCase() === 'high' ? 'destructive' :
                        alert.severity.toLowerCase() === 'medium' ? 'warning' : 
                        'default'
                      } className="text-xs px-1 py-0 h-auto leading-tight">
                        {alert.severity}
                      </Badge>
                    </div>
                    {/* Example Action Button (optional)
                    <div>
                      <Button 
                        variant="outline" 
                        size="xs"
                        className="h-6 text-xs"
                        onClick={() => toast({ title: 'Block Action (Simulated)', description: `Request to block ${alert.source_ip}`})}
                      >
                        Block IP
                      </Button>
                    </div>
                    */}
                  </div>
                ))}
              </div>
            </ScrollArea>
          </div>
        ) : (
          <div className="text-center text-muted-foreground py-8">
            <Shield size={48} className="mx-auto mb-2 opacity-50" />
            No recent Port Scan alerts.
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default PortScanningSimulation;