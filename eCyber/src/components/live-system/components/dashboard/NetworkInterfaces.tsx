
import { useState } from "react";
import { ArrowDown, ArrowUp, Network, RefreshCw, ExternalLink, WifiOff } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger
} from "@/components/ui/accordion";
import { NetworkInterface } from "../../lib/socket";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

interface NetworkInterfacesProps {
  interfaces: NetworkInterface[];
}

export function NetworkInterfaces({ interfaces }: NetworkInterfacesProps) {
  const [expandedItems, setExpandedItems] = useState<string[]>([]);
  
  const handleToggle = (value: string) => {
    setExpandedItems(prev => 
      prev.includes(value)
        ? prev.filter(item => item !== value)
        : [...prev, value]
    );
  };

  const handleRefreshInterface = (interfaceName: string) => {
    toast.info(`Refreshing ${interfaceName} interface...`, {
      description: "Reconnection attempt initiated"
    });
    
    setTimeout(() => {
      toast.success(`${interfaceName} interface refreshed`, {
        description: "Reconnection successful"
      });
    }, 2500);
  };

  const handleDisableInterface = (interfaceName: string) => {
    toast.success(`${interfaceName} interface disabled`, {
      description: "Network interface is now disabled"
    });
  };

  const formatMacAddress = (mac: string) => {
    return mac.toUpperCase().replace(/:/g, "-");
  };

  return (
    <Card className="bg-card">
      <CardHeader className="pb-2 flex flex-row items-center space-y-0 gap-2">
        <Network className="h-5 w-5 text-muted-foreground" />
        <CardTitle>Network Interfaces</CardTitle>
        <span className="bg-secondary/50 text-xs px-2 py-0.5 rounded ml-2">
          {interfaces.length} Total
        </span>
      </CardHeader>
      <CardContent>
        <Accordion type="multiple" className="w-full" value={expandedItems} onValueChange={setExpandedItems}>
          {interfaces.map((intf, index) => (
            <AccordionItem 
              key={`${intf.name}-${index}`} 
              value={`item-${index}`}
              className="border border-muted/30 rounded-lg mt-2 overflow-hidden"
            >
              <AccordionTrigger 
                className="px-4 py-2 hover:bg-secondary/20 hover:no-underline"
                onClick={() => handleToggle(`item-${index}`)}
              >
                <div className="flex justify-between items-center w-full pr-4">
                  <div className="flex items-center gap-3">
                    <div className={cn(
                      "w-2 h-2 rounded-full",
                      intf.status === "up" ? "bg-cyber-alert-green" : "bg-cyber-alert-red"
                    )} />
                    <span className="font-medium">{intf.name}</span>
                  </div>
                  <div className="flex items-center">
                    {intf.status === "up" ? (
                      <div className="flex items-center text-xs text-muted-foreground">
                        <ArrowUp className="h-3 w-3 mr-1 text-cyber-alert-green" />
                        <span>Up</span>
                        {intf.speed > 0 && (
                          <span className="ml-2 bg-secondary/50 px-1.5 py-0.5 rounded-sm">
                            {intf.speed} Mbps
                          </span>
                        )}
                      </div>
                    ) : (
                      <div className="flex items-center text-xs text-muted-foreground">
                        <ArrowDown className="h-3 w-3 mr-1 text-cyber-alert-red" />
                        <span>Down</span>
                      </div>
                    )}
                  </div>
                </div>
              </AccordionTrigger>
              <AccordionContent className="px-4 pb-3 pt-1">
                <div className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">IP Address</p>
                      <p className="text-sm font-mono">{intf.ipAddress}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">MAC Address</p>
                      <p className="text-sm font-mono">{formatMacAddress(intf.macAddress)}</p>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Speed</p>
                      <p className="text-sm">
                        {intf.speed > 0 ? `${intf.speed} Mbps` : "N/A"}
                      </p>
                    </div>
                  </div>
                  
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Details</p>
                    <div className="bg-secondary/20 rounded-md p-2">
                      <ul className="text-xs space-y-1">
                        <li><span className="text-muted-foreground">Type:</span> {intf.name.includes("Wi") || intf.name.includes("Wireless") ? "Wireless" : "Wired"}</li>
                        <li><span className="text-muted-foreground">Status:</span> <span className={intf.status === "up" ? "text-cyber-alert-green" : "text-cyber-alert-red"}>{intf.status.toUpperCase()}</span></li>
                        <li><span className="text-muted-foreground">Media State:</span> {intf.status === "up" ? "Connected" : "Disconnected"}</li>
                        <li><span className="text-muted-foreground">Interface Description:</span> {intf.name}</li>
                      </ul>
                    </div>
                  </div>
                  
                  <div className="flex gap-2">
                    <Button 
                      variant="outline" 
                      size="sm"
                      onClick={() => handleRefreshInterface(intf.name)}
                      className="h-7 text-xs flex gap-1 items-center"
                    >
                      <RefreshCw className="h-3 w-3" /> Refresh
                    </Button>
                    {intf.status === "up" && (
                      <Button 
                        variant="destructive" 
                        size="sm"
                        onClick={() => handleDisableInterface(intf.name)}
                        className="h-7 text-xs flex gap-1 items-center"
                      >
                        <WifiOff className="h-3 w-3" /> Disable
                      </Button>
                    )}
                    <Button 
                      variant="outline" 
                      size="sm"
                      className="h-7 text-xs flex gap-1 items-center ml-auto"
                      onClick={() => toast.info(`More details for ${intf.name}`, { description: "Opening detailed network interface information" })}
                    >
                      <ExternalLink className="h-3 w-3" /> More Details
                    </Button>
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      </CardContent>
    </Card>
  );
}
