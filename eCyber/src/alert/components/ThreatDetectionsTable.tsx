
import React from "react";
import DataTable from "./DataTable";
import { ThreatDetection } from "@/types";
import ThreatBadge from "./ThreatBadge";

interface ThreatDetectionsTableProps {
  threats: ThreatDetection[];
  className?: string;
}

const ThreatDetectionsTable = ({ threats, className }: ThreatDetectionsTableProps) => {
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const columns = [
    // {
    //   key: "id",
    //   header: "Threat ID",
    //   cell: (threat: ThreatDetection) => <span className="font-mono text-xs">{threat.id}</span>,
    //   sortable: true,
    // },
    {
      key: "message",
      header: "Message",
      cell: (threat: ThreatDetection) => <span>{threat.message}</span>,
      sortable: true,
    },
    {
      key: "severity",
      header: "Severity",
      cell: (threat: ThreatDetection) => <ThreatBadge severity={threat.severity} />,
      sortable: true,
    },
    {
      key: "sourceIp",
      header: "Source IP",
      cell: (threat: ThreatDetection) => <span className="font-mono text-xs">{threat.sourceIp}</span>,
      sortable: true,
    },
    {
      key: "targetSystem",
      header: "Target System",
      cell: (threat: ThreatDetection) => <span>{threat.targetSystem}</span>,
      sortable: true,
    },
    {
      key: "timestamp",
      header: "Timestamp",
      cell: (threat: ThreatDetection) => <span>{formatTimestamp(threat.timestamp)}</span>,
      sortable: true,
    },
    {
      key: "iocs",
      header: "Related IOCs",
      cell: (threat: ThreatDetection) => (
        <div className="flex flex-wrap gap-1">
          {threat.iocs.slice(0, 2).map((ioc, index) => (
            <span 
              key={index} 
              className="bg-muted px-1.5 py-0.5 rounded text-xs"
            >
              {ioc}
            </span>
          ))}
          {threat.iocs.length > 2 && (
            <span className="text-xs text-muted-foreground">
              +{threat.iocs.length - 2} more
            </span>
          )}
        </div>
      ),
    },
    {
      key: "mitigationStatus",
      header: "Mitigation Status",
      cell: (threat: ThreatDetection) => (
        <span className={`inline-flex px-2 py-1 rounded-full text-xs ${
          threat.mitigationStatus === "Auto-mitigated" 
            ? "bg-threat-low/10 text-threat-low" 
            : "bg-threat-high/10 text-threat-high"
        }`}>
          {threat.mitigationStatus}
        </span>
      ),
      sortable: true,
    },
  ];

  return (
    <DataTable columns={columns} data={threats} className={className} />
  );
};

export default ThreatDetectionsTable;
