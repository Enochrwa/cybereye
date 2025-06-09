
import React from "react";
import { cn } from "@/lib/utils";
import { Circle, CircleCheck, CircleX } from "lucide-react";

interface StatusIndicatorProps {
  status: "Online" | "Offline";
  className?: string;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
  labelClassName?: string;
}

const StatusIndicator = ({ 
  status, 
  className, 
  size = "md",
  showLabel = true,
  labelClassName
}: StatusIndicatorProps) => {
  const isOnline = status === "Online";
  
  const sizeClasses = {
    sm: "w-3 h-3",
    md: "w-4 h-4",
    lg: "w-5 h-5"
  };

  return (
    <div className={cn("flex items-center gap-1.5", className)}>
      {isOnline ? (
        <CircleCheck className={cn(
          sizeClasses[size],
          "text-threat-low animate-pulse"
        )} />
      ) : (
        <CircleX className={cn(
          sizeClasses[size],
          "text-threat-critical"
        )} />
      )}
      {showLabel && (
        <span className={cn(
          "text-sm font-medium",
          isOnline ? "text-threat-low" : "text-threat-critical",
          labelClassName
        )}>
          {status}
        </span>
      )}
    </div>
  );
};

export default StatusIndicator;
