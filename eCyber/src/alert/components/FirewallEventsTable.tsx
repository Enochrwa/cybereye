
import React from "react";
import DataTable from "./DataTable";
import { FirewallEvent } from "@/types";

interface FirewallEventsTableProps {
  events: FirewallEvent[];
  className?: string;
}

const FirewallEventsTable = ({ events, className }: FirewallEventsTableProps) => {
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
      key: "ipAddress",
      header: "IP Address",
      cell: (event: FirewallEvent) => (
        <span className="font-mono text-xs">{event.ipAddress}</span>
      ),
      sortable: true,
    },
    {
      key: "action",
      header: "Action",
      cell: (event: FirewallEvent) => (
        <span className={`inline-flex px-2 py-1 rounded-full text-xs ${
          event.action === "Blocked"
            ? "bg-threat-critical/10 text-threat-critical" 
            : "bg-threat-low/10 text-threat-low"
        }`}>
          {event.action}
        </span>
      ),
      sortable: true,
    },
    {
      key: "reason",
      header: "Reason",
      cell: (event: FirewallEvent) => <span>{event.reason}</span>,
      sortable: true,
    },
    {
      key: "ruleTrigger",
      header: "Rule Triggered",
      cell: (event: FirewallEvent) => (
        <span className="text-xs bg-muted px-2 py-1 rounded">
          {event.ruleTrigger}
        </span>
      ),
      sortable: true,
    },
    {
      key: "geoLocation",
      header: "Geo-location",
      cell: (event: FirewallEvent) => <span>{event.geoLocation}</span>,
      sortable: true,
    },
    {
      key: "timestamp",
      header: "Timestamp",
      cell: (event: FirewallEvent) => <span>{formatTimestamp(event.timestamp)}</span>,
      sortable: true,
    },
  ];

  return (
    <DataTable columns={columns} data={events} className={className} />
  );
};

export default FirewallEventsTable;
