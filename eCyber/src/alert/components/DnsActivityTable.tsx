
import React from "react";
import DataTable from "./DataTable";
import { DnsActivity } from "@/types";
import { AlertCircle } from "lucide-react";

interface DnsActivityTableProps {
  activities: DnsActivity[];
  className?: string;
}

const DnsActivityTable = ({ activities, className }: DnsActivityTableProps) => {
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const columns = [
    {
      key: "timestamp",
      header: "Timestamp",
      cell: (activity: DnsActivity) => <span>{formatTimestamp(activity.timestamp)}</span>,
      sortable: true,
    },
    {
      key: "domain",
      header: "Domain",
      cell: (activity: DnsActivity) => (
        <div className="flex items-center gap-1">
          <span className="font-mono text-xs">{activity.domain}</span>
          {activity.possibleDGA && (
            <AlertCircle className="w-4 h-4 text-threat-high" />
          )}
        </div>
      ),
      sortable: true,
    },
    {
      key: "recordType",
      header: "Record Type",
      cell: (activity: DnsActivity) => (
        <span className="bg-muted px-2 py-0.5 rounded text-xs">{activity.recordType}</span>
      ),
      sortable: true,
    },
    {
      key: "queryResult",
      header: "Result",
      cell: (activity: DnsActivity) => <span className="font-mono text-xs">{activity.queryResult}</span>,
      sortable: true,
    },
    {
      key: "ttl",
      header: "TTL",
      cell: (activity: DnsActivity) => <span>{activity.ttl}s</span>,
      sortable: true,
    },
    {
      key: "clientIp",
      header: "Client IP",
      cell: (activity: DnsActivity) => <span className="font-mono text-xs">{activity.clientIp}</span>,
      sortable: true,
    },
    {
      key: "threatIntel",
      header: "Threat Intel Match",
      cell: (activity: DnsActivity) => (
        <span className={`inline-flex px-2 py-1 rounded-full text-xs ${
          activity.matchedThreatIntel
            ? "bg-threat-critical/10 text-threat-critical" 
            : "bg-threat-low/10 text-threat-low"
        }`}>
          {activity.matchedThreatIntel ? "Matched" : "Clean"}
        </span>
      ),
      sortable: true,
    },
  ];

  return (
    <DataTable columns={columns} data={activities} className={className} />
  );
};

export default DnsActivityTable;
