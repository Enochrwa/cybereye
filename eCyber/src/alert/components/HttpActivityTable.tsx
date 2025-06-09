
import React from "react";
import DataTable from "./DataTable";
import { HttpActivity } from "../types";


interface HttpActivityTableProps {
  activities: HttpActivity[];
  className?: string;
}

const HttpActivityTable = ({ activities, className }: HttpActivityTableProps) => {
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const getStatusCodeClass = (statusCode: number) => {
    if (statusCode < 300) return "text-threat-low";
    if (statusCode < 400) return "text-threat-medium";
    if (statusCode < 500) return "text-threat-high";
    return "text-threat-critical";
  };

  const getThreatScoreClass = (score: number) => {
    if (score < 30) return "text-threat-low";
    if (score < 60) return "text-threat-medium";
    if (score < 80) return "text-threat-high";
    return "text-threat-critical";
  };

  const columns = [
    {
      key: "timestamp",
      header: "Timestamp",
      cell: (activity: HttpActivity) => <span>{formatTimestamp(activity.timestamp)}</span>,
      sortable: true,
    },
    {
      key: "method",
      header: "Method",
      cell: (activity: HttpActivity) => (
        <span className="font-medium px-2 py-0.5 rounded bg-muted">{activity.method}</span>
      ),
      sortable: true,
    },
    {
      key: "path",
      header: "Path",
      cell: (activity: HttpActivity) => (
        <span className="font-mono text-xs truncate max-w-[200px] inline-block">{activity.path}</span>
      ),
      sortable: true,
    },
    {
      key: "statusCode",
      header: "Status",
      cell: (activity: HttpActivity) => (
        <span className={`font-medium ${getStatusCodeClass(activity.statusCode)}`}>
          {activity.statusCode}
        </span>
      ),
      sortable: true,
    },
    {
      key: "sourceIp",
      header: "Source IP",
      cell: (activity: HttpActivity) => <span className="font-mono text-xs">{activity.sourceIp}</span>,
      sortable: true,
    },
    {
      key: "destinationIp",
      header: "Destination IP",
      cell: (activity: HttpActivity) => <span className="font-mono text-xs">{activity.destinationIp}</span>,
      sortable: true,
    },
    {
      key: "securityIssues",
      header: "Security Issues",
      cell: (activity: HttpActivity) => (
        <div className="flex flex-wrap gap-1">
          {activity?.missingSecurityHeaders?.length > 0 && (
            <span className="bg-threat-high/10 text-threat-high px-1.5 py-0.5 rounded text-xs">
              Missing Headers
            </span>
          )}
          {activity.injectionDetected && (
            <span className="bg-threat-critical/10 text-threat-critical px-1.5 py-0.5 rounded text-xs">
              Injection
            </span>
          )}
          {activity.beaconingIndicators && (
            <span className="bg-threat-medium/10 text-threat-medium px-1.5 py-0.5 rounded text-xs">
              Beaconing
            </span>
          )}
        </div>
      ),
    },
    {
      key: "threatScore",
      header: "Threat Score",
      cell: (activity: HttpActivity) => (
        <div className="flex items-center">
          <div className="h-2 w-full max-w-24 bg-muted rounded-full overflow-hidden mr-2">
            <div 
              className={`h-full ${
                activity.threatScore < 30 
                  ? "bg-threat-low" 
                  : activity.threatScore < 60 
                  ? "bg-threat-medium" 
                  : activity.threatScore < 80 
                  ? "bg-threat-high" 
                  : "bg-threat-critical"
              }`}
              style={{ width: `${activity.threatScore}%` }}
            />
          </div>
          <span className={`text-xs font-medium ${getThreatScoreClass(activity.threatScore)}`}>
            {activity.threatScore}
          </span>
        </div>
      ),
      sortable: true,
    }
  ];

  return (
    <DataTable columns={columns} data={activities} className={className} />
  );
};

export default HttpActivityTable;
