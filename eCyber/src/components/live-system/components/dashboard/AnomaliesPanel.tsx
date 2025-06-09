
import { AlertTriangle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger
} from "@/components/ui/accordion";
import { AnomalyItem } from "../../lib/socket";
import { cn } from "../../lib/utils";

interface AnomaliesPanelProps {
  anomalies: AnomalyItem[];
}

export function AnomaliesPanel({ anomalies }: AnomaliesPanelProps) {
  if (anomalies.length === 0) {
    return null;
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "low":
        return "bg-cyber-alert-blue text-cyber-alert-blue";
      case "medium":
        return "bg-cyber-alert-amber text-cyber-alert-amber";
      case "high":
        return "bg-cyber-alert-red text-cyber-alert-red";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  return (
    <Card className="bg-card border-cyber-alert-red/30 shadow-sm shadow-cyber-alert-red/10">
      <CardHeader className="pb-2 flex flex-row items-center space-y-0 gap-2">
        <AlertTriangle className="h-5 w-5 text-cyber-alert-red animate-pulse" />
        <CardTitle>Anomalies & Threats</CardTitle>
      </CardHeader>
      <CardContent>
        <Accordion type="single" collapsible className="w-full">
          {anomalies.map((anomaly, index) => (
            <AccordionItem 
              key={`${anomaly.title}-${index}`} 
              value={`item-${index}`}
              className={cn(
                "border border-muted/30 rounded-lg mt-2 overflow-hidden",
                anomaly.severity === "high" && "bg-cyber-alert-red/5 shadow-sm shadow-cyber-alert-red/10"
              )}
            >
              <AccordionTrigger className="px-4 py-2 hover:bg-secondary/20 hover:no-underline">
                <div className="flex items-center gap-3 text-left">
                  <div className={cn(
                    "w-2 h-2 rounded-full",
                    getSeverityColor(anomaly.severity)
                  )} />
                  <div>
                    <div className="font-medium text-sm">{anomaly.title}</div>
                    <div className="text-xs text-muted-foreground">
                      {anomaly.timestamp}
                    </div>
                  </div>
                </div>
              </AccordionTrigger>
              <AccordionContent className="px-4 pb-3 pt-1">
                <div className="flex gap-4 items-start">
                  <div className="flex items-center justify-center">
                    <div className={cn(
                      "px-2 py-1 rounded-full text-xs uppercase font-medium",
                      anomaly.severity === "high" ? "bg-cyber-alert-red/20 text-cyber-alert-red" :
                      anomaly.severity === "medium" ? "bg-cyber-alert-amber/20 text-cyber-alert-amber" :
                      "bg-cyber-alert-blue/20 text-cyber-alert-blue"
                    )}>
                      {anomaly.severity}
                    </div>
                  </div>
                  <div>
                    <p className="text-sm">{anomaly.description}</p>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </CardContent>
    </Card>
  );
}
