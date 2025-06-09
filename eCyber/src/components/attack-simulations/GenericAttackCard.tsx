import React, { useMemo } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardDescription } from "@/components/ui/card";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

// Copied from eCyber/src/pages/AttackSimulations.tsx
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

interface GenericAttackCardProps {
  attackName: string;
  alerts: AlertData[];
  icon?: React.ReactNode;
}

const GenericAttackCard: React.FC<GenericAttackCardProps> = ({ attackName, alerts, icon }) => {
  const processedChartData = useMemo(() => {
    if (!alerts || alerts.length === 0) {
      return [];
    }

    // Aggregate alerts by time window (e.g., per 5 seconds)
    const timeWindow = 5000; // 5 seconds in milliseconds
    const alertCountsByTime: { [key: string]: number } = {};

    alerts.forEach(alert => {
      const alertTime = new Date(alert.timestamp).getTime();
      const windowStart = Math.floor(alertTime / timeWindow) * timeWindow;
      const windowKey = new Date(windowStart).toLocaleTimeString();

      if (alertCountsByTime[windowKey]) {
        alertCountsByTime[windowKey]++;
      } else {
        alertCountsByTime[windowKey] = 1;
      }
    });

    return Object.entries(alertCountsByTime)
      .map(([time, count]) => ({ time, count }))
      .sort((a, b) => new Date(`1/1/1970 ${a.time}`).getTime() - new Date(`1/1/1970 ${b.time}`).getTime()); // Basic time sort

  }, [alerts]);

  const recentAlerts = useMemo(() => {
    return alerts.slice(0, 5);
  }, [alerts]);

  return (
    <Card className="w-full flex flex-col h-full">
      <CardHeader>
        <div className="flex items-center justify-between">
          <CardTitle className="text-lg font-semibold text-isimbi-purple">
            {attackName}
          </CardTitle>
          {icon && <div className="text-isimbi-purple">{icon}</div>}
        </div>
        <CardDescription>Real-time simulation and alert monitoring</CardDescription>
      </CardHeader>
      <CardContent className="flex-grow flex flex-col space-y-4">
        <div className="h-60"> {/* Ensure chart has a defined height */}
          {processedChartData.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={processedChartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'hsl(var(--background))',
                    borderColor: 'hsl(var(--border))',
                  }}
                />
                <Legend />
                <Line type="monotone" dataKey="count" stroke="#8884d8" activeDot={{ r: 8 }} name="Alerts" />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-full text-muted-foreground">
              No chart data available.
            </div>
          )}
        </div>

        <div>
          <h3 className="text-md font-semibold mb-2">Recent Alerts:</h3>
          {recentAlerts.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Timestamp</TableHead>
                  <TableHead>Source IP</TableHead>
                  <TableHead>Destination IP</TableHead>
                  <TableHead>Description</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {recentAlerts.map((alert) => (
                  <TableRow key={alert.id}>
                    <TableCell>{new Date(alert.timestamp).toLocaleTimeString()}</TableCell>
                    <TableCell>{alert.source_ip}</TableCell>
                    <TableCell>{alert.destination_ip}</TableCell>
                    <TableCell className="truncate max-w-xs">{alert.description}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground">No alerts detected yet.</p>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default GenericAttackCard;
export type { AlertData }; // Export AlertData for use in other components if needed
