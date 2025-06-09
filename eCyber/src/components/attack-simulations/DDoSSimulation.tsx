
import React, { useState, useEffect } from 'react';
import { AlertCircle, ShieldAlert, Zap, Loader2 } from 'lucide-react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { SimulationAlert } from '@/components/common/ai-assistant/types';
import { 
  ChartContainer, 
  ChartTooltip, 
  ChartTooltipContent, 
  ChartLegend, 
} from "@/components/ui/chart"; 
import { 
  ResponsiveContainer, 
  LineChart, 
  Line, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  Legend 
} from "recharts";

import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";

// Shared AlertData interface
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

interface DDoSSimulationProps {
  alerts: AlertData[];
}

const DDoSSimulation: React.FC<DDoSSimulationProps> = ({ alerts }) => {
  const { toast } = useToast();

  // Removed useState for ddosAlerts and useEffect that handled mock data or old socket listeners
  // Alerts are now directly consumed from props

  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader className="bg-gradient-to-r from-isimbi-navy to-isimbi-dark-charcoal">
        <CardTitle className="flex items-center gap-2 text-white">
          <ShieldAlert className="h-5 w-5 text-isimbi-purple" />
          Detected DDoS Activity
        </CardTitle>
        <CardDescription className="text-gray-300">
          Real-time monitoring of detected Distributed Denial of Service attacks.
        </CardDescription>
      </CardHeader>

      <CardContent className="p-6">
        {alerts && alerts.length > 0 ? (
          <ScrollArea className="h-[400px] border rounded-md">
            <div className="divide-y">
              {alerts.map((alert) => (
                <Alert key={alert.id} className={`p-3 m-0 border-0 border-b rounded-none ${
                  alert.severity === 'Critical' ? 'bg-red-900/20 border-red-700' : 
                  alert.severity === 'High' ? 'bg-orange-700/20 border-orange-600' : 
                  alert.severity === 'Medium' ? 'bg-yellow-600/20 border-yellow-500' :
                  'bg-blue-600/20 border-blue-500'}` // Added Medium and a default
                }>
                  <ShieldAlert className={`h-5 w-5 mt-1 ${
                    alert.severity === 'Critical' ? 'text-red-400' : 
                    alert.severity === 'High' ? 'text-orange-400' : 
                    alert.severity === 'Medium' ? 'text-yellow-400' :
                    'text-blue-400'}`
                  } />
                  <div className="ml-2">
                    <AlertTitle className="font-semibold text-sm mb-0.5">
                      {alert.description} {alert.destination_ip && `(Target: ${alert.destination_ip}:${alert.destination_port})`}
                    </AlertTitle>
                    <AlertDescription className="text-xs text-muted-foreground space-y-0.5">
                      <div>Timestamp: {new Date(alert.timestamp).toLocaleString()}</div>
                      <div>Severity: <Badge variant={
                          alert.severity === 'Critical' || alert.severity === 'High' ? 'destructive' :
                          alert.severity === 'Medium' ? 'warning' : 'default'
                        } className="text-xs px-1 py-0 h-auto leading-tight">
                          {alert.severity}
                        </Badge>
                      </div>
                      {alert.source_ip && <div>Source IP(s): {alert.source_ip}</div>}
                      {alert.metadata?.probability && <div>Confidence: {(alert.metadata.probability * 100).toFixed(2)}%</div>}
                      {alert.protocol && <div>Protocol: {alert.protocol}</div>}
                    </AlertDescription>
                    <Button 
                      variant="outline" 
                      size="xs" 
                      className="mt-2 h-6 text-xs"
                      onClick={() => toast({ title: 'Mitigation Action (Simulated)', description: `Initiating mitigation for alert ID: ${alert.id.substring(0,8)}`})}
                    >
                      Simulate Mitigation
                    </Button>
                  </div>
                </Alert>
              ))}
            </div>
          </ScrollArea>
        ) : (
          <div className="text-center text-muted-foreground py-8">
            <ShieldAlert size={48} className="mx-auto mb-2 opacity-30" />
            No recent DDoS alerts.
          </div>
        )}
      </CardContent>
      <CardFooter className="bg-card/50 border-t border-border/50 py-3">
        <div className="text-xs text-muted-foreground">
          Monitoring for DDoS attack indicators...
        </div>
      </CardFooter>
    </Card>
  );
};

export default DDoSSimulation;