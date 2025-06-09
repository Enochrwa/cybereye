import React from 'react';
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Eye, Download } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { ThreatLog } from '@/types/logs';
import { exportToCSV, exportToJSON } from "@/lib/data-utils";

interface ThreatLogsTableProps {
  logs: ThreatLog[];
  onViewDetails: (log: ThreatLog) => void;
}

const ThreatLogsTable: React.FC<ThreatLogsTableProps> = ({ logs, onViewDetails }) => {
  const handleExportCSV = () => {
    exportToCSV(logs, 'threat-logs');
  };

  const handleExportJSON = () => {
    exportToJSON(logs, 'threat-logs');
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
              <TableHead>Service</TableHead>
              <TableHead>Message</TableHead>
              <TableHead>Location</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {logs.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="text-center py-8 text-muted-foreground">
                  No threat logs found
                </TableCell>
              </TableRow>
            ) : (
              logs.map((log) => (
                <TableRow key={log.id} className="bg-red-500/5">
                  <TableCell>{log.timestamp}</TableCell>
                  <TableCell>
                    <Badge variant="destructive">
                      {log.event_type}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="text-xs font-medium">{log.src_ip}</span>
                      <span className="text-xs text-muted-foreground">{log.src_mac}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex flex-col">
                      <span className="text-xs font-medium">{log.dest_ip}</span>
                      <span className="text-xs text-muted-foreground">Port: {log.port}</span>
                    </div>
                  </TableCell>
                  <TableCell>{log.service}</TableCell>
                  <TableCell>
                    <div className="max-w-[150px] truncate" title={log.message}>
                      {log.message}
                    </div>
                  </TableCell>
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

export default ThreatLogsTable;
