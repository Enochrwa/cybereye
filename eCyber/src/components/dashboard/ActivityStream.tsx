
import React from 'react';
import { cn } from '@/lib/utils';
import { format } from 'date-fns';
import { Shield, ShieldAlert, ShieldCheck, ShieldX, Info } from 'lucide-react';

type ActivityType = 'threat' | 'auth' | 'system' | 'network';
type SeverityType = 'info' | 'warning' | 'critical' | 'blocked';

interface Activity {
  id: string;
  type: ActivityType;
  severity: SeverityType;
  message: string;
  details?: string;
  source?: string;
  destination?: string;
  timestamp: Date;
}

interface ActivityStreamProps {
  activities: Activity[];
  className?: string;
  maxItems?: number;
}

const ActivityIcon: React.FC<{ type: ActivityType; severity: SeverityType }> = ({ type, severity }) => {
  if (type === 'threat') {
    if (severity === 'critical') return <ShieldAlert className="h-5 w-5 text-red-400" />;
    if (severity === 'warning') return <ShieldX className="h-5 w-5 text-amber-400" />;
    if (severity === 'blocked') return <ShieldCheck className="h-5 w-5 text-green-400" />;
    return <Shield className="h-5 w-5 text-blue-400" />;
  }
  
  return <Info className="h-5 w-5 text-muted-foreground" />;
};

const ActivityStream: React.FC<ActivityStreamProps> = ({ 
  activities, 
  className,
  maxItems = 10,
}) => {
  return (
    <div className={cn("space-y-1", className)}>
      {activities.slice(0, maxItems).map((activity, idx) => (
        <div 
          key={idx} 
          className="glass-card p-3 transition-all hover:bg-card"
        >
          <div className="flex">
            <div className="mr-3 flex-shrink-0">
              <ActivityIcon type={activity.type} severity={activity.severity} />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-start justify-between">
                <p className="text-sm font-medium truncate">
                  {activity.message}
                </p>
                <span className="text-xs text-muted-foreground ml-2 whitespace-nowrap">
                  {format(activity.timestamp, 'HH:mm')}
                </span>
              </div>
              
              {activity.details && (
                <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                  {activity.details}
                </p>
              )}
              
              {(activity.source || activity.destination) && (
                <div className="flex items-center mt-1.5 text-xs">
                  {activity.source && (
                    <code className="bg-secondary/50 px-1.5 py-0.5 rounded text-xs font-mono">
                      {activity.source}
                    </code>
                  )}
                  
                  {activity.source && activity.destination && (
                    <span className="mx-1.5 text-muted-foreground">→</span>
                  )}
                  
                  {activity.destination && (
                    <code className="bg-secondary/50 px-1.5 py-0.5 rounded text-xs font-mono">
                      {activity.destination}
                    </code>
                  )}
                </div>
              )}
              
              <div className="mt-2 flex items-center space-x-2">
                <span className={cn(
                  "inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold",
                  `severity-${activity.severity}`
                )}>
                  {activity.severity}
                </span>
                
                <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-secondary/50 text-xs">
                  {activity.type}
                </span>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

export default ActivityStream;
