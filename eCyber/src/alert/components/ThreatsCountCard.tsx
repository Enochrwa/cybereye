
import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ThreatCount } from "../types";
import ThreatBadge from "./ThreatBadge";

interface ThreatsCountCardProps {
  threatCounts: ThreatCount[];
  className?: string;
}

const ThreatsCountCard = ({ threatCounts, className }: ThreatsCountCardProps) => {
  const totalThreats = Array.isArray(threatCounts)
    ? threatCounts.reduce((acc, threat) => acc + threat.count, 0)
    : 0;

  return (
    <Card className={className}>
      <CardHeader className="pb-2">
        <CardTitle className="text-lg font-medium">Active Threats</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col space-y-3">
          <div className="text-3xl font-bold">
            {totalThreats}
            <span className="text-sm font-normal text-muted-foreground ml-2">total</span>
          </div>
          <div className="grid grid-cols-2 gap-2">
          {Array.isArray(threatCounts) &&
            threatCounts.map((threat) => (
              <div 
                key={threat.severity} 
                className="flex items-center justify-between p-2 rounded-md bg-card border"
              >
                <ThreatBadge severity={threat.severity} />
                <span className="text-lg font-semibold">{threat.count}</span>
              </div>
            ))}
        </div>

        </div>
      </CardContent>
    </Card>
  );
};

export default ThreatsCountCard;
