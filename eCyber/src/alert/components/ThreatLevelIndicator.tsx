
import React from "react";
import { cn } from "@/lib/utils";
import { Shield, ShieldAlert } from "lucide-react";

interface ThreatLevelIndicatorProps {
  level: "Critical" | "High" | "Medium" | "Low";
  description?: string;
  className?: string;
}

const ThreatLevelIndicator = ({ 
  level, 
  description,
  className 
}: ThreatLevelIndicatorProps) => {
  const getColor = () => {
    switch (level) {
      case "Critical": return "threat-critical";
      case "High": return "threat-high"; 
      case "Medium": return "threat-medium";
      case "Low": return "threat-low";
      default: return "threat-low";
    }
  };

  const colorClass = getColor();
  const bgColorClass = `bg-${colorClass}`;
  const textColorClass = `text-${colorClass}`;

  return (
    <div className={cn("flex flex-col items-center", className)}>
      <div className="relative mb-3">
        <div className={cn(
          "w-20 h-20 rounded-full flex items-center justify-center",
          `bg-${colorClass}/20`,
          textColorClass
        )}>
          <div className={cn(
            "absolute w-full h-full rounded-full",
            `border-4 border-${colorClass}/40`,
            level === "Critical" && "animate-pulse-ring"
          )}></div>
          {level === "Critical" || level === "High" ? (
            <ShieldAlert className="w-8 h-8" />
          ) : (
            <Shield className="w-8 h-8" />
          )}
        </div>
      </div>
      <h3 className={cn(
        "text-xl font-semibold mb-1", 
        textColorClass
      )}>
        {level}
      </h3>
      {description && (
        <p className="text-sm text-muted-foreground text-center max-w-xs">
          {description}
        </p>
      )}
    </div>
  );
};

export default ThreatLevelIndicator;
