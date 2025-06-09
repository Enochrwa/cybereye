import React from 'react';
import { HttpActivity as StoreHttpActivity } from '@/hooks/usePacketSnifferSocket'; // Assuming this is the correct path
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { cn } from '@/lib/utils';

export interface HttpActivityViewProps {
  activities: StoreHttpActivity[];
}

const HttpActivityView: React.FC<HttpActivityViewProps> = ({ activities }) => {
  const truncateString = (str: string | undefined | null, num: number) => {
    if (!str) return 'N/A';
    if (str.length <= num) {
      return str;
    }
    return str.slice(0, num) + '...';
  };

  const getRiskBadgeVariant = (riskLevel?: string | null): "default" | "destructive" | "secondary" | "outline" => {
    switch (riskLevel?.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'destructive';
      case 'medium':
        return 'secondary'; // Shadcn secondary often orange/yellow or use custom
      case 'low':
        return 'default'; // Shadcn default often blue/gray
      default:
        return 'outline';
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>HTTP Activity Log</CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-72 w-full rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Timestamp</TableHead>
                <TableHead>Source IP</TableHead>
                <TableHead>Dest. IP</TableHead>
                <TableHead>Method</TableHead>
                <TableHead>Host</TableHead>
                <TableHead>Path</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>User Agent</TableHead>
                <TableHead>Risk Level</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(!activities || activities.length === 0) ? (
                <TableRow>
                  <TableCell colSpan={9} className="h-24 text-center">
                    No HTTP activity to display.
                  </TableCell>
                </TableRow>
              ) : (
                activities.map((activity) => (
                  <TableRow key={activity.id}>
                    <TableCell>{new Date(activity.timestamp).toLocaleString()}</TableCell>
                    <TableCell>{activity.source_ip}</TableCell>
                    <TableCell>{activity.destination_ip}</TableCell>
                    <TableCell>{activity.method}</TableCell>
                    <TableCell>{truncateString(activity.host, 30)}</TableCell>
                    <TableCell>{truncateString(activity.path, 40)}</TableCell>
                    <TableCell>{activity.status_code}</TableCell>
                    <TableCell>{truncateString(activity.user_agent, 30)}</TableCell>
                    <TableCell>
                      <Badge variant={getRiskBadgeVariant(activity.risk_level)}>
                        {activity.risk_level || 'N/A'}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </ScrollArea>
      </CardContent>
    </Card>
  );
};

export default HttpActivityView;
