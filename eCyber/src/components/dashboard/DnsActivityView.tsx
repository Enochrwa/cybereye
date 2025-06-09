import React from 'react';
import { DnsActivityData as StoreDnsActivityData } from '@/hooks/usePacketSnifferSocket'; // Assuming this is the correct path
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

export interface DnsActivityViewProps {
  activities: StoreDnsActivityData[];
}

const DnsActivityView: React.FC<DnsActivityViewProps> = ({ activities }) => {
  const truncateString = (str: string | undefined | null, num: number) => {
    if (!str) return 'N/A';
    if (str.length <= num) {
      return str;
    }
    return str.slice(0, num) + '...';
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>DNS Activity Log</CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-72 w-full rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Timestamp</TableHead>
                <TableHead>Source IP</TableHead>
                <TableHead>Query Name</TableHead>
                <TableHead>Query Type</TableHead>
                <TableHead>Response Data</TableHead>
                <TableHead>DGA Score</TableHead>
                <TableHead>Suspicious</TableHead>
                <TableHead>Tunnel</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(!activities || activities.length === 0) ? (
                <TableRow>
                  <TableCell colSpan={8} className="h-24 text-center">
                    No DNS activity to display.
                  </TableCell>
                </TableRow>
              ) : (
                activities.map((activity) => (
                  <TableRow key={activity.id || `${activity.timestamp}-${activity.source_ip}-${activity.queries?.[0]?.query_name}`}>
                    <TableCell>{new Date(activity.timestamp).toLocaleString()}</TableCell>
                    <TableCell>{activity.source_ip}</TableCell>
                    <TableCell>{truncateString(activity.queries?.[0]?.query_name, 30)}</TableCell>
                    <TableCell>{activity.queries?.[0]?.query_type || 'N/A'}</TableCell>
                    <TableCell>{truncateString(activity.responses?.[0]?.response_data, 30)}</TableCell>
                    <TableCell>{activity.dga_score?.toFixed(2) ?? 'N/A'}</TableCell>
                    <TableCell>
                      <Badge variant={activity.is_suspicious ? 'destructive' : 'outline'}>
                        {activity.is_suspicious ? 'Yes' : 'No'}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={activity.tunnel_detected ? 'destructive' : 'outline'}>
                        {activity.tunnel_detected ? 'Yes' : 'No'}
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

export default DnsActivityView;
