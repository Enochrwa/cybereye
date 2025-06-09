
import React from "react";
import { cn } from "@/lib/utils";
import { ThreatSeverity } from "@/types";
import { Shield, ShieldAlert } from "lucide-react";

interface ThreatBadgeProps {
  severity: ThreatSeverity;
  showIcon?: boolean;
  className?: string;
}

const ThreatBadge = ({ severity, showIcon = true, className }: ThreatBadgeProps) => {
  const getColorClass = () => {
    switch (severity) {
      case "Critical":
        return "text-threat-critical bg-threat-critical/10";
      case "High":
        return "text-threat-high bg-threat-high/10";
      case "Medium":
        return "text-threat-medium bg-threat-medium/10";
      case "Low":
        return "text-threat-low bg-threat-low/10";
      default:
        return "text-muted-foreground bg-muted/50";
    }
  };

  const getIcon = () => {
    switch (severity) {
      case "Critical":
      case "High":
        return <ShieldAlert className="w-4 h-4" />;
      default:
        return <Shield className="w-4 h-4" />;
    }
  };

  return (
    <div className={cn(
      "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium",
      getColorClass(),
      className
    )}>
      {showIcon && getIcon()}
      {severity}
    </div>
  );
};

export default ThreatBadge;
