import React from 'react';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Eye, Download } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { NetworkEventLog } from '@/types/logs';
import { exportToCSV, exportToJSON } from "@/lib/data-utils";

interface NetworkEventsTableProps {
  logs: NetworkEventLog[];
  onViewDetails: (log: NetworkEventLog) => void;
}

const NetworkEventsTable: React.FC<NetworkEventsTableProps> = ({ logs, onViewDetails }) => {
  const handleExportCSV = () => {
    exportToCSV(logs, 'network-event-logs');
  };

  const handleExportJSON = () => {
    exportToJSON(logs, 'network-event-logs');
  };

  return (
    <div className="w-full">
      <div className="flex justify-end mb-4 gap-2">
        <Button variant="outline" size="sm" onClick={handleExportCSV}>
          <Download className="h-4 w-4 mr-2" />
          Export CSV
        </Button>
        <Button variant="outline" size="sm" onClick={handleExportJSON}>
          <Download className="h-4 w-4 mr-2" />
          Export JSON
        </Button>
      </div>
      
      <div className="border rounded-md">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Timestamp</TableHead>
              <TableHead>Event Type</TableHead>
              <TableHead>Source</TableHead>
              <TableHead>Destination</TableHead>
              <TableHead>Protocol</TableHead>
              <TableHead>Application</TableHead>
              <TableHead>Location</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="text-center py-8 text-muted-foreground">
                  No network events found
                </TableCell>
              </TableRow>
            ) : (
              logs.map((log) => (
                <TableRow key={log.id}>
                  <TableCell>{log.timestamp}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className="bg-blue-500/10 text-blue-500 hover:bg-blue-500/20 hover:text-blue-500">
                      {log.event_type}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="text-xs font-medium">{log.source_ip}</span>
                      <span className="text-xs text-muted-foreground">{log.source_mac}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="text-xs font-medium">{log.destination_ip}</span>
                      <span className="text-xs text-muted-foreground">Port: {log.destination_port}</span>
                    </div>
                  </TableCell>
                  <TableCell>{log.protocol}</TableCell>
                  <TableCell>{log.application}</TableCell>
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="text-xs font-medium">{log.geo.country}</span>
                      <span className="text-xs text-muted-foreground">{log.geo.city}</span>
                    </div>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="icon" onClick={() => onViewDetails(log)}>
                      <Eye className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
};

export default NetworkEventsTable;