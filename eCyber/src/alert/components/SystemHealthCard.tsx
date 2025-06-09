
import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SystemStatus } from "@/types";
import StatusIndicator from "./StatusIndicator";

interface SystemHealthCardProps {
  systems: SystemStatus[];
  className?: string;
}

const SystemHealthCard = ({ systems, className }: SystemHealthCardProps) => {
  const onlineCount = systems.filter(system => system.status === "Online").length;
  
  return (
    <Card className={className}>
      <CardHeader className="pb-2">
        <CardTitle className="text-lg font-medium">System Health</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col space-y-3">
          <div className="text-3xl font-bold">
            {onlineCount}/{systems.length}
            <span className="text-sm font-normal text-muted-foreground ml-2">systems online</span>
          </div>
          <div className="space-y-2">
            {systems.map((system) => (
              <div 
                key={system.name}
                className="flex items-center justify-between p-2 rounded-md bg-card border"
              >
                <div>
                  <p className="font-medium">{system.name}</p>
                  <p className="text-xs text-muted-foreground">{system.statusMessage}</p>
                </div>
                <StatusIndicator status={system.status} />
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default SystemHealthCard;
