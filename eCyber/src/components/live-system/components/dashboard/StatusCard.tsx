import { cn } from "@/lib/utils";
import { SystemOverviewItem } from "../../lib/socket";
import { 
  Shield, Cpu, Database, HardDrive, Network, 
  Activity, Clock, Info, AlertTriangle, Check, 
  Server, Thermometer, Battery
} from "lucide-react";

interface StatusCardProps {
  item: SystemOverviewItem;
  onClick?: () => void;
}

export function StatusCard({ item, onClick }: StatusCardProps) {
  const getStatusColor = (color?: string) => {
    if (!color) return "bg-secondary text-secondary-foreground";
    
    switch (color) {
      case "red":
        return "bg-cyber-alert-red/20 text-cyber-alert-red border-cyber-alert-red/50";
      case "orange":
        return "bg-cyber-alert-amber/20 text-cyber-alert-amber border-cyber-alert-amber/50";
      case "green":
        return "bg-cyber-alert-green/20 text-cyber-alert-green border-cyber-alert-green/50";
      case "blue":
        return "bg-cyber-alert-blue/20 text-cyber-alert-blue border-cyber-alert-blue/50";
      default:
        return "bg-secondary text-secondary-foreground";
    }
  };

  const getIcon = () => {
    switch (item.icon) {
      case "shield":
        return <Shield className="h-5 w-5" />;
      case "cpu":
        return <Cpu className="h-5 w-5" />;
      case "memory-stick": // Changed from "memory" to "memory-stick"
        return <HardDrive className="h-5 w-5" />; // Using HardDrive instead of Memory 
      case "hard-drive":
        return <HardDrive className="h-5 w-5" />;
      case "network":
        return <Network className="h-5 w-5" />;
      case "activity":
        return <Activity className="h-5 w-5" />;
      case "clock":
        return <Clock className="h-5 w-5" />;
      case "server":
        return <Server className="h-5 w-5" />;
      case "thermometer":
        return <Thermometer className="h-5 w-5" />;
      case "battery":
        return <Battery className="h-5 w-5" />;
      default:
        return <Info className="h-5 w-5" />;
    }
  };
  
  return (
    <div 
      className={cn(
        "flex flex-col p-4 rounded-lg border transition-all",
        "border-border/50 bg-card hover:bg-card/80",
        item.color ? "hover:shadow-md hover:shadow-" + item.color + "/10" : "",
        item.color && item.color === "red" ? "animate-pulse" : "",
        onClick ? "cursor-pointer" : ""
      )}
      onClick={onClick}
    >
      <div className="flex justify-between items-center mb-2">
        <h3 className="text-sm font-medium text-muted-foreground">{item.title}</h3>
        <div className={cn(
          "rounded-full p-1",
          item.color ? `text-cyber-alert-${item.color}` : "text-muted-foreground"
        )}>
          {getIcon()}
        </div>
      </div>
      
      <div className="flex items-center gap-2">
        <p className="text-xl font-semibold">{item.value}</p>
        {item.color === "red" && (
          <AlertTriangle className="h-4 w-4 text-cyber-alert-red animate-pulse" />
        )}
        {item.color === "green" && (
          <Check className="h-4 w-4 text-cyber-alert-green" />
        )}
      </div>
      
      {item.details && (
        <p className="mt-1 text-xs text-muted-foreground">{item.details}</p>
      )}
    </div>
  );
}