
import React from "react";
import DataTable from "./DataTable";
import { ThreatResponse } from "@/types";

interface ThreatResponseTableProps {
  responses: ThreatResponse[];
  className?: string;
}

const ThreatResponseTable = ({ responses, className }: ThreatResponseTableProps) => {
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
      cell: (response: ThreatResponse) => <span>{formatTimestamp(response.timestamp)}</span>,
      sortable: true,
    },
    {
      key: "action",
      header: "Action",
      cell: (response: ThreatResponse) => <span className="font-medium">{response.action}</span>,
      sortable: true,
    },
    {
      key: "target",
      header: "Target",
      cell: (response: ThreatResponse) => <span className="font-mono text-xs">{response.target}</span>,
      sortable: true,
    },
    {
      key: "status",
      header: "Status",
      cell: (response: ThreatResponse) => (
        <span className={`inline-flex px-2 py-1 rounded-full text-xs ${
          response.status === "Success"
            ? "bg-threat-low/10 text-threat-low" 
            : "bg-threat-critical/10 text-threat-critical"
        }`}>
          {response.status}
        </span>
      ),
      sortable: true,
    },
    {
      key: "details",
      header: "Details",
      cell: (response: ThreatResponse) => <span>{response.details}</span>,
    },
  ];

  return (
    <DataTable columns={columns} data={responses} className={className} />
  );
};

export default ThreatResponseTable;
