
import { Check, Shield, X, AlertTriangle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SecurityOverview as SecurityOverviewType} from "../../lib/socket";
import { cn } from "@/lib/utils";
import { useToast } from "@/hooks/use-toast";
import { motion } from "framer-motion";

interface SecurityOverviewProps {
  data: SecurityOverviewType;
}

export function SecurityOverview({ data }: SecurityOverviewProps) {
  const { toast } = useToast();
  
  const getStatusIcon = (value: string | number) => {
    if (typeof value === "number") {
      return value === 0 ? (
        <motion.div 
          initial={{ scale: 0.8 }}
          animate={{ scale: 1 }}
          transition={{ duration: 0.3 }}
          className="h-6 w-6 rounded-full bg-cyber-alert-green/20 flex items-center justify-center"
        >
          <Check className="h-4 w-4 text-cyber-alert-green" />
        </motion.div>
      ) : (
        <motion.div 
          initial={{ scale: 0.8 }}
          animate={{ scale: 1 }}
          transition={{ 
            duration: 0.3,
            repeat: 2,
            repeatType: "reverse" 
          }}
          className="h-6 w-6 rounded-full bg-cyber-alert-red/20 flex items-center justify-center"
        >
          <AlertTriangle className="h-4 w-4 text-cyber-alert-red" />
        </motion.div>
      );
    }
    
    return value === "Enabled" ? (
      <motion.div 
        initial={{ scale: 0.8 }}
        animate={{ scale: 1 }}
        transition={{ duration: 0.3 }}
        className="h-6 w-6 rounded-full bg-cyber-alert-green/20 flex items-center justify-center"
      >
        <Check className="h-4 w-4 text-cyber-alert-green" />
      </motion.div>
    ) : (
      <motion.div 
        initial={{ scale: 0.8 }}
        animate={{ scale: 1 }}
        transition={{ duration: 0.3 }}
        className="h-6 w-6 rounded-full bg-cyber-alert-red/20 flex items-center justify-center"
      >
        <X className="h-4 w-4 text-cyber-alert-red" />
      </motion.div>
    );
  };

  const handleStatusClick = (title: string, status: string | number) => {
    const statusText = typeof status === "number" 
      ? status === 0 ? "No issues detected" : `${status} issues detected`
      : status;
    
    toast({
      title: `${title} Status`,
      description: statusText,
      variant: isGoodStatus(status) ? "default" : "destructive"
    });
  };

  const isGoodStatus = (value: string | number) => {
    if (typeof value === "number") {
      return value === 0;
    }
    return value === "Enabled";
  };

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.1
      }
    }
  };

  const itemVariants = {
    hidden: { y: 20, opacity: 0 },
    visible: {
      y: 0,
      opacity: 1,
      transition: {
        duration: 0.6,
        ease: "easeOut"
      }
    }
  };

  return (
    <Card className="bg-card backdrop-blur-sm border-border/50 hover:shadow-lg hover:shadow-cyber-chart-purple/5 transition-all duration-300">
      <CardHeader className="pb-2 flex flex-row items-center space-y-0 gap-2">
        <motion.div
          initial={{ rotate: -10 }}
          animate={{ rotate: 0 }}
          transition={{ duration: 0.5 }}
        >
          <Shield className="h-5 w-5 text-cyber-alert-blue" />
        </motion.div>
        <CardTitle>Security Overview</CardTitle>
      </CardHeader>
      <CardContent>
        <motion.div 
          className="grid grid-cols-2 md:grid-cols-4 gap-4"
          variants={containerVariants}
          initial="hidden"
          animate="visible"
        >
          {/* Firewall Status */}
          <motion.div 
            className={cn(
              "flex items-center gap-3 p-3 border border-border/50 rounded-lg cursor-pointer",
              "hover:bg-secondary/30 transition-colors duration-300",
              !isGoodStatus(data.firewall) && "animate-pulse"
            )}
            variants={itemVariants}
            onClick={() => handleStatusClick("Firewall", data.firewall)}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            {getStatusIcon(data.firewall)}
            <div>
              <p className="text-sm font-medium">Firewall</p>
              <p className={cn(
                "text-xs",
                data.firewall === "Enabled" ? "text-cyber-alert-green" : "text-cyber-alert-red"
              )}>
                {data.firewall}
              </p>
            </div>
          </motion.div>

          {/* Suspicious Connections */}
          <motion.div 
            className={cn(
              "flex items-center gap-3 p-3 border border-border/50 rounded-lg cursor-pointer",
              "hover:bg-secondary/30 transition-colors duration-300",
              data.suspiciousConnections > 0 && "animate-pulse"
            )}
            variants={itemVariants}
            onClick={() => handleStatusClick("Suspicious Connections", data.suspiciousConnections)}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            {getStatusIcon(data.suspiciousConnections)}
            <div>
              <p className="text-sm font-medium">Suspicious Connections</p>
              <p className={cn(
                "text-xs",
                data.suspiciousConnections === 0 ? "text-cyber-alert-green" : "text-cyber-alert-red"
              )}>
                {data.suspiciousConnections}
              </p>
            </div>
          </motion.div>

          {/* Suspicious Processes */}
          <motion.div 
            className={cn(
              "flex items-center gap-3 p-3 border border-border/50 rounded-lg cursor-pointer",
              "hover:bg-secondary/30 transition-colors duration-300",
              data.suspiciousProcesses > 0 && "animate-pulse"
            )}
            variants={itemVariants}
            onClick={() => handleStatusClick("Suspicious Processes", data.suspiciousProcesses)}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            {getStatusIcon(data.suspiciousProcesses)}
            <div>
              <p className="text-sm font-medium">Suspicious Processes</p>
              <p className={cn(
                "text-xs",
                data.suspiciousProcesses === 0 ? "text-cyber-alert-green" : "text-cyber-alert-red"
              )}>
                {data.suspiciousProcesses}
              </p>
            </div>
          </motion.div>

          {/* System Updates */}
          <motion.div 
            className={cn(
              "flex items-center gap-3 p-3 border border-border/50 rounded-lg cursor-pointer",
              "hover:bg-secondary/30 transition-colors duration-300",
              data.systemUpdates !== "Enabled" && "animate-pulse"
            )}
            variants={itemVariants}
            onClick={() => handleStatusClick("System Updates", data.systemUpdates)}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            {getStatusIcon(data.systemUpdates)}
            <div>
              <p className="text-sm font-medium">System Updates</p>
              <p className={cn(
                "text-xs",
                data.systemUpdates === "Enabled" ? "text-cyber-alert-green" : "text-cyber-alert-red"
              )}>
                {data.systemUpdates}
              </p>
            </div>
          </motion.div>
        </motion.div>
      </CardContent>
    </Card>
  );
}
