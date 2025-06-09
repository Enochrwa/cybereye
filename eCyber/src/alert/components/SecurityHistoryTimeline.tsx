
import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import { ThreatDetection, PhishingDetection, 
  FirewallEvent, 
  HttpActivity, 
  DnsActivity, 
  PacketAnalysis, 
  ThreatResponse, 
  QuarantinedFile,
  IPv6Activity } from "../types";

type TimelineEvent = {
  id: string;
  timestamp: string;
  type: string;
  title: string;
  description: string;
  severity?: "Critical" | "High" | "Medium" | "Low";
};

interface SecurityHistoryTimelineProps {
  threats: ThreatDetection[];
  phishing: PhishingDetection[];
  firewall: FirewallEvent[];
  http: HttpActivity[];
  dns: DnsActivity[];
  packets: PacketAnalysis[];
  responses: ThreatResponse[];
  quarantined: QuarantinedFile[];
  ipv6: IPv6Activity[];
  className?: string;
}

const SecurityHistoryTimeline = ({
  threats,
  phishing,
  firewall,
  http,
  dns,
  packets,
  responses,
  quarantined,
  ipv6,
  className
}: SecurityHistoryTimelineProps) => {
  const [filter, setFilter] = useState<string>("all");
  
  // Convert all events to a common timeline format
  const allEvents: TimelineEvent[] = [
    ...threats.map(t => ({
      id: t.id,
      timestamp: t.timestamp,
      type: "threat",
      title: `Threat Detected: ${t.message}`,
      description: `Source: ${t.sourceIp}, Target: ${t.targetSystem}`,
      severity: t.severity
    })),
    ...phishing.map(p => ({
      id: crypto.randomUUID(),
      timestamp: p.timestamp,
      type: "phishing",
      title: `Phishing URL: ${p?.url?.substring(0, 30)}...`,
      description: `Confidence: ${p.confidenceScore.toFixed(1)}%, Categories: ${p.categories.join(', ')}`,
      severity: p.confidenceScore > 80 ? "High" : p.confidenceScore > 50 ? "Medium" : "Low" as "High" | "Medium" | "Low"
    })),
    ...firewall.map(f => ({
      id: crypto.randomUUID(),
      timestamp: f.timestamp,
      type: "firewall",
      title: `Firewall ${f.action}: ${f.ipAddress}`,
      description: `Reason: ${f.reason}, Rule: ${f.ruleTrigger}`,
      severity: f.action === "Blocked" ? "Medium" : "Low" as "Medium" | "Low"
    })),
    ...http.map(h => ({
      id: h.id,
      timestamp: h.timestamp,
      type: "http",
      title: `HTTP ${h.method} ${h?.path?.substring(0, 30)}...`,
      description: `Status: ${h.statusCode}, Threat Score: ${h.threatScore}`,
      severity: h.threatScore > 80 ? "Critical" : h.threatScore > 60 ? "High" : h.threatScore > 30 ? "Medium" : "Low" as "Critical" | "High" | "Medium" | "Low"
    })),
    ...dns.map(d => ({
      id: d.id,
      timestamp: d.timestamp,
      type: "dns",
      title: `DNS Query: ${d.domain}`,
      description: `Type: ${d.recordType}, Client: ${d.clientIp}`,
      severity: d.matchedThreatIntel ? "High" : d.possibleDGA ? "Medium" : "Low" as "High" | "Medium" | "Low"
    })),
    ...packets.map(p => ({
      id: p.id,
      timestamp: p.timestamp,
      type: "packet",
      title: `${p.protocol} Packet: ${p.sourceIp} → ${p.destinationIp}`,
      description: p.anomalyDetected 
        ? `Anomaly: ${p.anomalyDetected}`
        : `Ports: ${p.sourcePort} → ${p.destinationPort}`,
      severity: p.anomalyDetected ? "High" : p.suspiciousPatterns ? "Medium" : "Low" as "High" | "Medium" | "Low"
    })),
    ...responses.map(r => ({
      id: r.id,
      timestamp: r.timestamp,
      type: "response",
      title: `Security Response: ${r.action}`,
      description: `Target: ${r.target}, Status: ${r.status}`,
      severity: r.status === "Failure" ? "High" : "Medium" as "High" | "Medium"
    })),
    ...quarantined.map(q => ({
      id: q.id,
      timestamp: q.timestamp,
      type: "quarantine",
      title: `File Quarantined: ${q.filePath.split('/').pop() || q.filePath}`,
      description: `Reason: ${q.reason}, Process: ${q.originalProcess}`,
      severity: "High" as const
    })),
    ...ipv6.map(i => ({
      id: i.id,
      timestamp: i.timestamp,
      type: "ipv6",
      title: `IPv6 Traffic: ${i.protocol}`,
      description: `${i.sourceIPv6?.substring(0, 20)}... → ${i.destinationIPv6?.substring(0, 20)}...`,
      severity: i.tunneled ? "Medium" : i.baselineDeviation > 50 ? "Medium" : "Low" as "Medium" | "Low"
    }))
  ];
  
  // Sort events by timestamp (newest first)
  const sortedEvents = [...allEvents].sort((a, b) => 
    new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );
  
  // Apply filter
  const filteredEvents = filter === "all" 
    ? sortedEvents 
    : sortedEvents.filter(e => e.type === filter);

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
  };

  const getSeverityClass = (severity?: string) => {
    switch (severity) {
      case "Critical": return "border-threat-critical bg-threat-critical/5";
      case "High": return "border-threat-high bg-threat-high/5";
      case "Medium": return "border-threat-medium bg-threat-medium/5";
      case "Low": return "border-threat-low bg-threat-low/5";
      default: return "border-muted";
    }
  };

  const getEventTypeClass = (type: string) => {
    switch (type) {
      case "threat": return "bg-threat-critical/10 text-threat-critical";
      case "phishing": return "bg-threat-high/10 text-threat-high";
      case "firewall": return "bg-primary/10 text-primary";
      case "http": return "bg-accent/80 text-accent-foreground";
      case "dns": return "bg-threat-medium/10 text-threat-medium";
      case "packet": return "bg-muted text-muted-foreground";
      case "response": return "bg-threat-low/10 text-threat-low";
      case "quarantine": return "bg-destructive/10 text-destructive";
      case "ipv6": return "bg-secondary/50 text-secondary-foreground";
      default: return "bg-muted text-muted-foreground";
    }
  };

  return (
    <Card className={className}>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>Security Event Timeline</span>
          <Tabs defaultValue="all" value={filter} onValueChange={setFilter} className="w-auto">
            <TabsList>
              <TabsTrigger value="all">All</TabsTrigger>
              <TabsTrigger value="threat">Threats</TabsTrigger>
              <TabsTrigger value="http">HTTP</TabsTrigger>
              <TabsTrigger value="dns">DNS</TabsTrigger>
              <TabsTrigger value="packet">Packets</TabsTrigger>
              <TabsTrigger value="response">Responses</TabsTrigger>
            </TabsList>
          </Tabs>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="relative pl-6 border-l border-border space-y-4 max-h-96 overflow-y-auto pr-2">
          {filteredEvents.length > 0 ? (
            filteredEvents.map((event) => (
              <div 
                key={`${event.type}-${event.id}`}
                className={`relative p-3 rounded-md border ${getSeverityClass(event.severity)}`}
              >
                <div className="absolute w-3 h-3 rounded-full bg-background border-2 border-border left-[-22px] top-4" />
                <div className="flex flex-col space-y-1">
                  <div className="flex items-center justify-between">
                    <span className={`text-xs px-2 py-0.5 rounded ${getEventTypeClass(event.type)}`}>
                      {event.type.charAt(0).toUpperCase() + event.type.slice(1)}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      {formatTimestamp(event.timestamp)}
                    </span>
                  </div>
                  <h4 className="text-sm font-medium">{event.title}</h4>
                  <p className="text-xs text-muted-foreground">{event.description}</p>
                </div>
              </div>
            ))
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              No events match the current filter
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

export default SecurityHistoryTimeline;
