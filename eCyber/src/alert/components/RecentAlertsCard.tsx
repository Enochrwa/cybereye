
import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ThreatDetection } from "@/types";
import ThreatBadge from "./ThreatBadge";

interface RecentAlertsCardProps {
  alerts: ThreatDetection[];
  className?: string;
}

const RecentAlertsCard = ({ alerts, className }: RecentAlertsCardProps) => {
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <Card className={className}>
      <CardHeader className="pb-2">
        <CardTitle className="text-lg font-medium">Recent Critical Alerts (Last 24 Hours)</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col space-y-3">
          {alerts.map(alert => (
            <div key={alert.id} className="p-2 rounded-md bg-card border">
              <div className="flex items-center justify-between mb-1">
                <ThreatBadge severity={alert.severity} />
                <span className="text-xs text-muted-foreground">{formatTimestamp(alert.timestamp)}</span>
              </div>
              <div className="flex items-start space-x-2">
                <div className="flex-1">
                  <p className="font-medium text-sm">{alert.message}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">
                    {alert.sourceIp} → {alert.targetSystem}
                  </p>
                </div>
                <div className={`text-xs px-2 py-0.5 rounded ${
                  alert.mitigationStatus === "Auto-mitigated" 
                  ? "bg-threat-low/10 text-threat-low" 
                  : "bg-threat-high/10 text-threat-high"
                }`}>
                  {alert.mitigationStatus}
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

export default RecentAlertsCard;
