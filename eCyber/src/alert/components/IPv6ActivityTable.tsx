
import React from "react";
import DataTable from "./DataTable";
import { IPv6Activity } from "../types";
interface IPv6ActivityTableProps {
  activities: IPv6Activity[];
  className?: string;
}

const IPv6ActivityTable = ({ activities, className }: IPv6ActivityTableProps) => {
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
      cell: (activity: IPv6Activity) => <span>{formatTimestamp(activity.timestamp)}</span>,
      sortable: true,
    },
    {
      key: "sourceIPv6",
      header: "Source IPv6",
      cell: (activity: IPv6Activity) => (
        <span className="font-mono text-xs">{activity.sourceIPv6}</span>
      ),
      sortable: true,
    },
    {
      key: "destinationIPv6",
      header: "Destination IPv6",
      cell: (activity: IPv6Activity) => (
        <span className="font-mono text-xs">{activity.destinationIPv6}</span>
      ),
      sortable: true,
    },
    {
      key: "protocol",
      header: "Protocol",
      cell: (activity: IPv6Activity) => (
        <span className="bg-muted px-2 py-0.5 rounded text-xs">{activity.protocol}</span>
      ),
      sortable: true,
    },
    {
      key: "payloadSize",
      header: "Payload Size",
      cell: (activity: IPv6Activity) => <span>{activity.payloadSize} bytes</span>,
      sortable: true,
    },
    {
      key: "baselineDeviation",
      header: "Baseline Deviation",
      cell: (activity: IPv6Activity) => {
        const deviationClass = activity.baselineDeviation > 50 
          ? "text-threat-high" 
          : activity.baselineDeviation > 25 
          ? "text-threat-medium" 
          : "text-threat-low";
        
        return (
          <div className="flex items-center">
            <div className="h-2 w-full max-w-24 bg-muted rounded-full overflow-hidden mr-2">
              <div 
                className={activity.baselineDeviation > 50 
                  ? "bg-threat-high" 
                  : activity.baselineDeviation > 25 
                  ? "bg-threat-medium" 
                  : "bg-threat-low"}
                style={{ width: `${activity.baselineDeviation}%` }}
              />
            </div>
            <span className={`text-xs ${deviationClass}`}>
              {activity.baselineDeviation.toFixed(1)}%
            </span>
          </div>
        );
      },
      sortable: true,
    },
    {
      key: "tunneled",
      header: "Tunneled Traffic",
      cell: (activity: IPv6Activity) => (
        <span className={`inline-flex px-2 py-1 rounded-full text-xs ${
          activity.tunneled
            ? "bg-threat-high/10 text-threat-high" 
            : "bg-threat-low/10 text-threat-low"
        }`}>
          {activity.tunneled ? "Yes" : "No"}
        </span>
      ),
      sortable: true,
    },
  ];

  return (
    <DataTable columns={columns} data={activities} className={className} />
  );
};

export default IPv6ActivityTable;
