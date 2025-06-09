
import React from "react";
import DataTable from "./DataTable";
import { PacketAnalysis } from "@/types";

interface PacketAnalysisTableProps {
  packets: PacketAnalysis[];
  className?: string;
}

const PacketAnalysisTable = ({ packets, className }: PacketAnalysisTableProps) => {
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getProtocolClass = (protocol: string) => {
    switch (protocol) {
      case "TCP": return "bg-primary/10 text-primary";
      case "UDP": return "bg-threat-medium/10 text-threat-medium";
      case "ICMP": return "bg-threat-high/10 text-threat-high";
      default: return "bg-muted text-muted-foreground";
    }
  };

  const columns = [
    {
      key: "timestamp",
      header: "Timestamp",
      cell: (packet: PacketAnalysis) => <span>{formatTimestamp(packet.timestamp)}</span>,
      sortable: true,
    },
    {
      key: "protocol",
      header: "Protocol",
      cell: (packet: PacketAnalysis) => (
        <span className={`px-2 py-0.5 rounded text-xs ${getProtocolClass(packet.protocol)}`}>
          {packet.protocol}
        </span>
      ),
      sortable: true,
    },
    {
      key: "sourceIp",
      header: "Source",
      cell: (packet: PacketAnalysis) => (
        <div>
          <span className="font-mono text-xs block">{packet.sourceIp}:{packet.sourcePort}</span>
          <span className="text-xs text-muted-foreground">{packet.geoLocationSource}</span>
        </div>
      ),
      sortable: true,
    },
    {
      key: "destinationIp",
      header: "Destination",
      cell: (packet: PacketAnalysis) => (
        <div>
          <span className="font-mono text-xs block">{packet.destinationIp}:{packet.destinationPort}</span>
          <span className="text-xs text-muted-foreground">{packet.geoLocationDestination}</span>
        </div>
      ),
      sortable: true,
    },
    {
      key: "payloadSize",
      header: "Size",
      cell: (packet: PacketAnalysis) => <span>{packet.payloadSize} bytes</span>,
      sortable: true,
    },
    {
      key: "suspiciousActivity",
      header: "Suspicious Activity",
      cell: (packet: PacketAnalysis) => (
        <div className="flex flex-wrap gap-1">
          {packet.highEntropy && (
            <span className="bg-threat-high/10 text-threat-high px-1.5 py-0.5 rounded text-xs">
              High Entropy
            </span>
          )}
          {packet.suspiciousPatterns && (
            <span className="bg-threat-critical/10 text-threat-critical px-1.5 py-0.5 rounded text-xs">
              Suspicious Patterns
            </span>
          )}
          {packet.anomalyDetected && (
            <span className="bg-threat-critical/10 text-threat-critical px-1.5 py-0.5 rounded text-xs">
              {packet.anomalyDetected}
            </span>
          )}
          {!packet.highEntropy && !packet.suspiciousPatterns && !packet.anomalyDetected && (
            <span className="bg-threat-low/10 text-threat-low px-1.5 py-0.5 rounded text-xs">
              None Detected
            </span>
          )}
        </div>
      )
    }
  ];

  return (
    <DataTable columns={columns} data={packets} className={className} />
  );
};

export default PacketAnalysisTable;
