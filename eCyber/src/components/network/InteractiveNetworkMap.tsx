
import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Globe, Activity, Eye, Settings, Shield } from 'lucide-react';
import { Button } from "@/components/ui/button";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { useToast } from "@/hooks/use-toast";

const InteractiveNetworkMap = () => {
  const [viewMode, setViewMode] = useState('topology');
  const [showLabels, setShowLabels] = useState(true);
  const [showTraffic, setShowTraffic] = useState(true);
  const { toast } = useToast();

  const handleFullScreen = () => {
    toast({
      title: "Full Screen Mode",
      description: "Network map expanded to full screen view",
    });
  };

  const handleViewChange = (value: string) => {
    if (value) setViewMode(value);
    toast({
      title: "View Changed",
      description: `Network map view updated to ${value === 'topology' ? 'Network Topology' : 
                     value === 'geo' ? 'Geographic' : 
                     value === 'traffic' ? 'Traffic Flow' : 'Security Zones'}`,
    });
  };

  const toggleLabels = () => {
    setShowLabels(!showLabels);
    toast({
      title: showLabels ? "Labels Hidden" : "Labels Shown",
      description: showLabels ? "Node labels are now hidden" : "Node labels are now visible",
    });
  };

  const toggleTraffic = () => {
    setShowTraffic(!showTraffic);
    toast({
      title: showTraffic ? "Traffic Flows Hidden" : "Traffic Flows Shown",
      description: showTraffic ? "Network traffic visualization hidden" : "Network traffic visualization enabled",
    });
  };

  // Different visualizations based on view mode
  const renderMap = () => {
    switch (viewMode) {
      case 'topology':
        return (
          <div className="relative">
            {/* Simulated network topology map */}
            <div className="h-[400px] flex items-center justify-center relative">
              {/* Core node */}
              <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-16 h-16 rounded-full bg-blue-500/30 border-2 border-blue-500 flex items-center justify-center z-20">
                {showLabels && <span className="text-xs font-medium">Core</span>}
              </div>
              
              {/* Network rings */}
              <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-48 h-48 rounded-full border border-dashed border-muted-foreground opacity-30"></div>
              <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 rounded-full border border-dashed border-muted-foreground opacity-20"></div>
              
              {/* Distribution layer nodes */}
              <div className="absolute top-1/2 left-[calc(50%-80px)] transform -translate-y-1/2 w-10 h-10 rounded-full bg-green-500/30 border-2 border-green-500 flex items-center justify-center z-10">
                {showLabels && <span className="text-xs font-medium">SW1</span>}
              </div>
              <div className="absolute top-[calc(50%-80px)] left-1/2 transform -translate-x-1/2 w-10 h-10 rounded-full bg-green-500/30 border-2 border-green-500 flex items-center justify-center z-10">
                {showLabels && <span className="text-xs font-medium">SW2</span>}
              </div>
              <div className="absolute top-1/2 left-[calc(50%+80px)] transform -translate-y-1/2 w-10 h-10 rounded-full bg-green-500/30 border-2 border-green-500 flex items-center justify-center z-10">
                {showLabels && <span className="text-xs font-medium">SW3</span>}
              </div>
              <div className="absolute top-[calc(50%+80px)] left-1/2 transform -translate-x-1/2 w-10 h-10 rounded-full bg-green-500/30 border-2 border-green-500 flex items-center justify-center z-10">
                {showLabels && <span className="text-xs font-medium">SW4</span>}
              </div>
              
              {/* Access layer nodes */}
              <div className="absolute top-[calc(50%-40px)] left-[calc(50%-120px)] w-8 h-8 rounded-full bg-amber-500/30 border-2 border-amber-500 flex items-center justify-center">
                {showLabels && <span className="text-[10px] font-medium">AP1</span>}
              </div>
              <div className="absolute top-[calc(50%-120px)] left-[calc(50%-40px)] w-8 h-8 rounded-full bg-amber-500/30 border-2 border-amber-500 flex items-center justify-center">
                {showLabels && <span className="text-[10px] font-medium">AP2</span>}
              </div>
              <div className="absolute top-[calc(50%-120px)] left-[calc(50%+40px)] w-8 h-8 rounded-full bg-amber-500/30 border-2 border-amber-500 flex items-center justify-center">
                {showLabels && <span className="text-[10px] font-medium">AP3</span>}
              </div>
              <div className="absolute top-[calc(50%-40px)] left-[calc(50%+120px)] w-8 h-8 rounded-full bg-amber-500/30 border-2 border-amber-500 flex items-center justify-center">
                {showLabels && <span className="text-[10px] font-medium">AP4</span>}
              </div>
              <div className="absolute top-[calc(50%+40px)] left-[calc(50%+120px)] w-8 h-8 rounded-full bg-amber-500/30 border-2 border-amber-500 flex items-center justify-center">
                {showLabels && <span className="text-[10px] font-medium">AP5</span>}
              </div>
              <div className="absolute top-[calc(50%+120px)] left-[calc(50%+40px)] w-8 h-8 rounded-full bg-amber-500/30 border-2 border-amber-500 flex items-center justify-center">
                {showLabels && <span className="text-[10px] font-medium">AP6</span>}
              </div>
              <div className="absolute top-[calc(50%+120px)] left-[calc(50%-40px)] w-8 h-8 rounded-full bg-amber-500/30 border-2 border-amber-500 flex items-center justify-center">
                {showLabels && <span className="text-[10px] font-medium">AP7</span>}
              </div>
              <div className="absolute top-[calc(50%+40px)] left-[calc(50%-120px)] w-8 h-8 rounded-full bg-amber-500/30 border-2 border-amber-500 flex items-center justify-center">
                {showLabels && <span className="text-[10px] font-medium">AP8</span>}
              </div>
              
              {/* Connection lines */}
              <svg className="absolute inset-0 w-full h-full" style={{ zIndex: 5 }}>
                {/* Core to distribution connections */}
                <line x1="50%" y1="50%" x2="calc(50% - 80px)" y2="50%" stroke="#3b82f6" strokeWidth="2" />
                <line x1="50%" y1="50%" x2="50%" y2="calc(50% - 80px)" stroke="#3b82f6" strokeWidth="2" />
                <line x1="50%" y1="50%" x2="calc(50% + 80px)" y2="50%" stroke="#3b82f6" strokeWidth="2" />
                <line x1="50%" y1="50%" x2="50%" y2="calc(50% + 80px)" stroke="#3b82f6" strokeWidth="2" />
                
                {/* Distribution to access connections */}
                <line x1="calc(50% - 80px)" y1="50%" x2="calc(50% - 120px)" y2="calc(50% - 40px)" stroke="#10b981" strokeWidth="1" />
                <line x1="calc(50% - 80px)" y1="50%" x2="calc(50% - 120px)" y2="calc(50% + 40px)" stroke="#10b981" strokeWidth="1" />
                
                <line x1="50%" y1="calc(50% - 80px)" x2="calc(50% - 40px)" y2="calc(50% - 120px)" stroke="#10b981" strokeWidth="1" />
                <line x1="50%" y1="calc(50% - 80px)" x2="calc(50% + 40px)" y2="calc(50% - 120px)" stroke="#10b981" strokeWidth="1" />
                
                <line x1="calc(50% + 80px)" y1="50%" x2="calc(50% + 120px)" y2="calc(50% - 40px)" stroke="#10b981" strokeWidth="1" />
                <line x1="calc(50% + 80px)" y1="50%" x2="calc(50% + 120px)" y2="calc(50% + 40px)" stroke="#10b981" strokeWidth="1" />
                
                <line x1="50%" y1="calc(50% + 80px)" x2="calc(50% - 40px)" y2="calc(50% + 120px)" stroke="#10b981" strokeWidth="1" />
                <line x1="50%" y1="calc(50% + 80px)" x2="calc(50% + 40px)" y2="calc(50% + 120px)" stroke="#10b981" strokeWidth="1" />
                
                {/* Traffic animation */}
                {showTraffic && (
                  <>
                    <circle r="3" fill="#3b82f6" opacity="0.7">
                      <animateMotion 
                        path="M 200,200 L 120,200" 
                        dur="3s" 
                        repeatCount="indefinite" 
                      />
                    </circle>
                    <circle r="3" fill="#3b82f6" opacity="0.7">
                      <animateMotion 
                        path="M 200,200 L 200,120" 
                        dur="2s" 
                        repeatCount="indefinite" 
                      />
                    </circle>
                    <circle r="3" fill="#3b82f6" opacity="0.7">
                      <animateMotion 
                        path="M 200,200 L 280,200" 
                        dur="4s" 
                        repeatCount="indefinite" 
                      />
                    </circle>
                    <circle r="3" fill="#3b82f6" opacity="0.7">
                      <animateMotion 
                        path="M 200,200 L 200,280" 
                        dur="3.5s" 
                        repeatCount="indefinite" 
                      />
                    </circle>
                  </>
                )}
              </svg>
              
              {/* Legend */}
              <div className="absolute bottom-2 left-2 bg-background/80 backdrop-blur-sm p-2 rounded-md border border-border text-xs">
                <div className="font-medium mb-1">Network Legend</div>
                <div className="flex items-center mb-1">
                  <div className="w-3 h-3 rounded-full bg-blue-500 mr-1"></div>
                  <span>Core Devices</span>
                </div>
                <div className="flex items-center mb-1">
                  <div className="w-3 h-3 rounded-full bg-green-500 mr-1"></div>
                  <span>Distribution Layer</span>
                </div>
                <div className="flex items-center">
                  <div className="w-3 h-3 rounded-full bg-amber-500 mr-1"></div>
                  <span>Access Layer</span>
                </div>
              </div>
            </div>
          </div>
        );
      
      case 'geo':
        return (
          <div className="h-[400px] relative flex items-center justify-center">
            {/* Simple world map simulation */}
            <div className="h-full w-full bg-blue-950/10 rounded-lg relative overflow-hidden">
              {/* Continents */}
              <div className="absolute top-[25%] left-[20%] w-[25%] h-[35%] bg-green-900/20 rounded-lg"></div>
              <div className="absolute top-[15%] left-[50%] w-[30%] h-[40%] bg-green-900/20 rounded-lg"></div>
              <div className="absolute top-[60%] left-[30%] w-[15%] h-[25%] bg-green-900/20 rounded-lg"></div>
              <div className="absolute top-[65%] left-[55%] w-[20%] h-[20%] bg-green-900/20 rounded-lg"></div>
              <div className="absolute top-[20%] left-[15%] w-[10%] h-[10%] bg-green-900/20 rounded-lg"></div>
              
              {/* Network nodes */}
              <div className="absolute top-[30%] left-[25%] w-4 h-4 rounded-full bg-red-500 animate-pulse"></div>
              <div className="absolute top-[25%] left-[55%] w-4 h-4 rounded-full bg-blue-500 animate-pulse"></div>
              <div className="absolute top-[65%] left-[65%] w-4 h-4 rounded-full bg-amber-500 animate-pulse"></div>
              <div className="absolute top-[40%] left-[35%] w-4 h-4 rounded-full bg-green-500 animate-pulse"></div>
              <div className="absolute top-[35%] left-[75%] w-4 h-4 rounded-full bg-purple-500 animate-pulse"></div>
              
              {/* Connection lines */}
              <svg className="absolute inset-0 w-full h-full" style={{ zIndex: 5 }}>
                <line x1="25%" y1="30%" x2="55%" y2="25%" stroke="rgba(255,255,255,0.3)" strokeWidth="1" strokeDasharray="5,5" />
                <line x1="25%" y1="30%" x2="35%" y2="40%" stroke="rgba(255,255,255,0.3)" strokeWidth="1" strokeDasharray="5,5" />
                <line x1="55%" y1="25%" x2="75%" y2="35%" stroke="rgba(255,255,255,0.3)" strokeWidth="1" strokeDasharray="5,5" />
                <line x1="35%" y1="40%" x2="65%" y2="65%" stroke="rgba(255,255,255,0.3)" strokeWidth="1" strokeDasharray="5,5" />
                
                {showTraffic && (
                  <>
                    <circle r="2" fill="#ffffff" opacity="0.7">
                      <animateMotion 
                        path="M 100,120 L 220,100" 
                        dur="5s" 
                        repeatCount="indefinite" 
                      />
                    </circle>
                    <circle r="2" fill="#ffffff" opacity="0.7">
                      <animateMotion 
                        path="M 100,120 L 140,160" 
                        dur="3s" 
                        repeatCount="indefinite" 
                      />
                    </circle>
                    <circle r="2" fill="#ffffff" opacity="0.7">
                      <animateMotion 
                        path="M 220,100 L 300,140" 
                        dur="4s" 
                        repeatCount="indefinite" 
                      />
                    </circle>
                  </>
                )}
              </svg>
              
              {showLabels && (
                <>
                  <div className="absolute top-[32%] left-[27%] text-[10px] text-white bg-black/50 px-1 rounded">NYC</div>
                  <div className="absolute top-[27%] left-[57%] text-[10px] text-white bg-black/50 px-1 rounded">London</div>
                  <div className="absolute top-[67%] left-[67%] text-[10px] text-white bg-black/50 px-1 rounded">Singapore</div>
                  <div className="absolute top-[42%] left-[37%] text-[10px] text-white bg-black/50 px-1 rounded">Chicago</div>
                  <div className="absolute top-[37%] left-[77%] text-[10px] text-white bg-black/50 px-1 rounded">Tokyo</div>
                </>
              )}
              
              {/* Legend */}
              <div className="absolute bottom-2 right-2 bg-background/80 backdrop-blur-sm p-2 rounded-md border border-border text-xs">
                <div className="font-medium mb-1">Data Centers</div>
                <div className="flex items-center mb-1">
                  <div className="w-3 h-3 rounded-full bg-red-500 mr-1"></div>
                  <span>Primary</span>
                </div>
                <div className="flex items-center mb-1">
                  <div className="w-3 h-3 rounded-full bg-blue-500 mr-1"></div>
                  <span>Secondary</span>
                </div>
                <div className="flex items-center">
                  <div className="w-3 h-3 rounded-full bg-green-500 mr-1"></div>
                  <span>Backup</span>
                </div>
              </div>
            </div>
          </div>
        );
      
      case 'traffic':
        return (
          <div className="h-[400px] flex flex-col">
            <div className="flex-1 border border-border rounded-md p-4 relative">
              {/* Traffic flow visualization */}
              <div className="h-full flex flex-col justify-evenly">
                {/* Network layers */}
                <div className="flex justify-between items-center py-2 border-b border-border">
                  <span className="text-sm font-medium">Internet</span>
                  <div className="w-2/3 bg-muted rounded-full h-3">
                    <div className="bg-blue-500 h-full rounded-full w-[85%] relative overflow-hidden">
                      {showTraffic && (
                        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-[shimmer_2s_infinite]"></div>
                      )}
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground">1.8 Gbps</span>
                </div>
                
                <div className="flex justify-between items-center py-2 border-b border-border">
                  <span className="text-sm font-medium">Edge Router</span>
                  <div className="w-2/3 bg-muted rounded-full h-3">
                    <div className="bg-blue-500 h-full rounded-full w-[75%] relative overflow-hidden">
                      {showTraffic && (
                        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-[shimmer_1.8s_infinite]"></div>
                      )}
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground">1.5 Gbps</span>
                </div>
                
                <div className="flex justify-between items-center py-2 border-b border-border">
                  <span className="text-sm font-medium">Core Switch</span>
                  <div className="w-2/3 bg-muted rounded-full h-3">
                    <div className="bg-blue-500 h-full rounded-full w-[65%] relative overflow-hidden">
                      {showTraffic && (
                        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-[shimmer_1.5s_infinite]"></div>
                      )}
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground">1.3 Gbps</span>
                </div>
                
                <div className="flex justify-between items-center py-2 border-b border-border">
                  <span className="text-sm font-medium">Distribution</span>
                  <div className="w-2/3 bg-muted rounded-full h-3">
                    <div className="bg-green-500 h-full rounded-full w-[45%] relative overflow-hidden">
                      {showTraffic && (
                        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-[shimmer_2s_infinite]"></div>
                      )}
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground">900 Mbps</span>
                </div>
                
                <div className="flex justify-between items-center py-2 border-b border-border">
                  <span className="text-sm font-medium">Access Layer</span>
                  <div className="w-2/3 bg-muted rounded-full h-3">
                    <div className="bg-green-500 h-full rounded-full w-[30%] relative overflow-hidden">
                      {showTraffic && (
                        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-[shimmer_2.2s_infinite]"></div>
                      )}
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground">600 Mbps</span>
                </div>
                
                <div className="flex justify-between items-center py-2">
                  <span className="text-sm font-medium">End Devices</span>
                  <div className="w-2/3 bg-muted rounded-full h-3">
                    <div className="bg-green-500 h-full rounded-full w-[15%] relative overflow-hidden">
                      {showTraffic && (
                        <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-[shimmer_2.5s_infinite]"></div>
                      )}
                    </div>
                  </div>
                  <span className="text-xs text-muted-foreground">300 Mbps</span>
                </div>
              </div>
            </div>
          </div>
        );
      
      case 'security':
        return (
          <div className="h-[400px] flex items-center justify-center relative">
            {/* Security zones visualization */}
            <div className="w-[350px] h-[350px] relative">
              {/* External zone */}
              <div className="absolute inset-0 bg-red-500/10 border border-red-500/30 rounded-full">
                {showLabels && (
                  <div className="absolute -top-6 left-1/2 transform -translate-x-1/2 text-xs text-red-500 font-medium">
                    External Zone
                  </div>
                )}
              </div>
              
              {/* DMZ */}
              <div className="absolute top-[15%] left-[15%] right-[15%] bottom-[15%] bg-amber-500/10 border border-amber-500/30 rounded-full">
                {showLabels && (
                  <div className="absolute -top-4 left-1/2 transform -translate-x-1/2 text-xs text-amber-500 font-medium">
                    DMZ
                  </div>
                )}
              </div>
              
              {/* Corporate zone */}
              <div className="absolute top-[30%] left-[30%] right-[30%] bottom-[30%] bg-blue-500/10 border border-blue-500/30 rounded-full">
                {showLabels && (
                  <div className="absolute -top-4 left-1/2 transform -translate-x-1/2 text-xs text-blue-500 font-medium">
                    Corporate Zone
                  </div>
                )}
              </div>
              
              {/* Protected zone */}
              <div className="absolute top-[45%] left-[45%] right-[45%] bottom-[45%] bg-green-500/10 border border-green-500/30 rounded-full">
                {showLabels && (
                  <div className="absolute top-[50%] left-[50%] transform -translate-x-1/2 -translate-y-1/2 text-xs text-green-500 font-medium">
                    Protected
                  </div>
                )}
              </div>
              
              {/* Network elements */}
              {/* External */}
              <div className="absolute top-[8%] left-[50%] transform -translate-x-1/2 w-6 h-6 rounded-md bg-red-500/30 border border-red-500 flex items-center justify-center">
                {showLabels && <span className="text-[8px]">FW1</span>}
              </div>
              
              {/* DMZ */}
              <div className="absolute top-[25%] left-[25%] w-5 h-5 rounded-md bg-amber-500/30 border border-amber-500 flex items-center justify-center">
                {showLabels && <span className="text-[8px]">WEB</span>}
              </div>
              <div className="absolute top-[25%] left-[75%] w-5 h-5 rounded-md bg-amber-500/30 border border-amber-500 flex items-center justify-center">
                {showLabels && <span className="text-[8px]">MAIL</span>}
              </div>
              
              {/* Corporate */}
              <div className="absolute top-[40%] left-[40%] w-4 h-4 rounded-md bg-blue-500/30 border border-blue-500 flex items-center justify-center">
                {showLabels && <span className="text-[7px]">APP</span>}
              </div>
              <div className="absolute top-[40%] left-[60%] w-4 h-4 rounded-md bg-blue-500/30 border border-blue-500 flex items-center justify-center">
                {showLabels && <span className="text-[7px]">ERP</span>}
              </div>
              
              {/* Protected */}
              <div className="absolute top-[50%] left-[50%] w-3 h-3 rounded-md bg-green-500/30 border border-green-500 flex items-center justify-center">
                {showLabels && <span className="text-[6px]">DB</span>}
              </div>
              
              {/* Traffic animations */}
              {showTraffic && (
                <svg className="absolute inset-0 w-full h-full">
                  <circle r="2" fill="#ef4444" opacity="0.7">
                    <animateMotion 
                      path="M 175,28 L 175,52" 
                      dur="1s" 
                      repeatCount="indefinite" 
                    />
                  </circle>
                  <circle r="2" fill="#f59e0b" opacity="0.7">
                    <animateMotion 
                      path="M 175,52 L 88,88" 
                      dur="1.5s" 
                      repeatCount="indefinite" 
                    />
                  </circle>
                  <circle r="2" fill="#f59e0b" opacity="0.7">
                    <animateMotion 
                      path="M 175,52 L 262,88" 
                      dur="1.5s" 
                      repeatCount="indefinite" 
                    />
                  </circle>
                  <circle r="2" fill="#3b82f6" opacity="0.7">
                    <animateMotion 
                      path="M 88,88 L 140,140" 
                      dur="2s" 
                      repeatCount="indefinite" 
                    />
                  </circle>
                  <circle r="2" fill="#3b82f6" opacity="0.7">
                    <animateMotion 
                      path="M 262,88 L 210,140" 
                      dur="2s" 
                      repeatCount="indefinite" 
                    />
                  </circle>
                  <circle r="2" fill="#22c55e" opacity="0.7">
                    <animateMotion 
                      path="M 140,140 L 175,175" 
                      dur="1.5s" 
                      repeatCount="indefinite" 
                    />
                  </circle>
                  <circle r="2" fill="#22c55e" opacity="0.7">
                    <animateMotion 
                      path="M 210,140 L 175,175" 
                      dur="1.5s" 
                      repeatCount="indefinite" 
                    />
                  </circle>
                </svg>
              )}
              
              {/* Legend */}
              <div className="absolute bottom-0 right-0 bg-background/80 backdrop-blur-sm p-1 rounded-md border border-border text-[10px]">
                <div className="font-medium mb-1">Security Zones</div>
                <div className="flex items-center mb-1">
                  <div className="w-2 h-2 rounded-full bg-red-500 mr-1"></div>
                  <span>External</span>
                </div>
                <div className="flex items-center mb-1">
                  <div className="w-2 h-2 rounded-full bg-amber-500 mr-1"></div>
                  <span>DMZ</span>
                </div>
                <div className="flex items-center mb-1">
                  <div className="w-2 h-2 rounded-full bg-blue-500 mr-1"></div>
                  <span>Corporate</span>
                </div>
                <div className="flex items-center">
                  <div className="w-2 h-2 rounded-full bg-green-500 mr-1"></div>
                  <span>Protected</span>
                </div>
              </div>
            </div>
          </div>
        );
        
      default:
        return (
          <div className="h-[400px] flex items-center justify-center">
            <Globe className="h-24 w-24 text-muted-foreground opacity-50" />
            <span className="ml-2 text-muted-foreground">Select a visualization type</span>
          </div>
        );
    }
  };

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-lg font-medium flex items-center justify-between">
          <div className="flex items-center">
            <Globe className="mr-2" size={18} />
            Network Topology
          </div>
          <div className="flex items-center space-x-2">
            <ToggleGroup type="single" value={viewMode} onValueChange={handleViewChange}>
              <ToggleGroupItem value="topology" aria-label="Network Topology">
                <Globe className="h-4 w-4" />
              </ToggleGroupItem>
              <ToggleGroupItem value="geo" aria-label="Geographic View">
                <Activity className="h-4 w-4" />
              </ToggleGroupItem>
              <ToggleGroupItem value="traffic" aria-label="Traffic Flow">
                <Activity className="h-4 w-4" />
              </ToggleGroupItem>
              <ToggleGroupItem value="security" aria-label="Security Zones">
                <Shield className="h-4 w-4" />
              </ToggleGroupItem>
            </ToggleGroup>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="border border-border rounded-lg flex flex-col bg-background/50">
          {renderMap()}
          
          <div className="border-t border-border p-2 flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Button variant="outline" size="sm" onClick={toggleLabels}>
                {showLabels ? "Hide Labels" : "Show Labels"}
              </Button>
              <Button variant="outline" size="sm" onClick={toggleTraffic}>
                {showTraffic ? "Hide Traffic" : "Show Traffic"}
              </Button>
            </div>
            <div className="flex items-center space-x-2">
              <Button variant="outline" size="sm" onClick={() => toast({ title: "Network Map Settings", description: "Map configuration opened" })}>
                <Settings className="mr-2 h-4 w-4" />
                Settings
              </Button>
              <Button size="sm" onClick={handleFullScreen}>
                <Eye className="mr-2 h-4 w-4" />
                Full Screen
              </Button>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

export default InteractiveNetworkMap;
