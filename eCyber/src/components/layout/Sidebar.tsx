
import React, { useState, useEffect } from 'react';
import axios from 'axios'
import { Link, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  ShieldAlert, 
  Globe, 
  FileBarChart, 
  Cpu, 
  Users, 
  Settings,
  Bell,
  AlertOctagon,
  Shield,
  Activity,
  AlertCircle,
  Zap,
  Network,
  Terminal,
  Database,
  Brain // Added Brain icon
} from 'lucide-react';
// If Brain icon wasn't available, I would use BarChartBig as an alternative:
// import { BarChartBig } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { 
  Sidebar as ShadcnSidebar,
  SidebarContent,
  SidebarHeader,
  SidebarFooter,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarSeparator,
  SidebarGroup,
  SidebarGroupLabel
} from "@/components/ui/sidebar";
import { SidebarProvider } from "@/components/ui/sidebar";

// Enhanced nav items with badge counts and severity
const navItems = [
  { icon: LayoutDashboard, label: 'Dashboard', path: '/dashboard', badge: null },
  { 
    icon: ShieldAlert, 
    label: 'Threat Intel', 
    path: '/threats', 
    badge: { count: 8, severity: 'critical' } 
  },
  { 
    icon: Globe, 
    label: 'Network Map', 
    path: '/network', 
    badge: { count: 3, severity: 'warning' }
  },
  { 
    icon: FileBarChart, 
    label: 'Logs', 
    path: '/logs', 
    badge: { count: 156, severity: 'info' } 
  },
  { 
    icon: Activity, 
    label: 'System', 
    path: '/system', 
    badge: { count: 7, severity: 'warning' } 
  },
  { 
    icon: AlertCircle, 
    label: 'Alerts', 
    path: '/alerts', 
    badge: { count: 7, severity: 'critical' } 
  },
  { icon: Cpu, label: 'ML & AI Models', path: '/models', badge: null },
  { icon: Users, label: 'Access Control', path: '/users', badge: null },
  { icon: Settings, label: 'Settings', path: '/settings', badge: null },
  { 
    icon: ShieldAlert, 
    label: 'Attacks', 
    path: '/attack-simulations', 
    badge: { count: 2, severity: 'warning' },
    highlight: true
  },
];

// Expanded attack simulations for new sidebar section
const attackSimulations = [
  { 
    id: 1, 
    name: 'DDoS Attack', 
    status: 'available', 
    icon: Network,
    path: '/attack-simulations',
    description: 'Volumetric network attacks'
  },
  { 
    id: 2, 
    name: 'Port Scanning', 
    status: 'available', 
    icon: Terminal,
    path: '/attack-simulations',
    description: 'Network reconnaissance'
  },
  { 
    id: 3, 
    name: 'SQL Injection', 
    status: 'available', 
    icon: Database,
    path: '/attack-simulations',
    description: 'Database vulnerabilities'
  },
  { 
    id: 4, 
    name: 'Phishing', 
    status: 'available', 
    icon: AlertOctagon,
    path: '/attack-simulations',
    description: 'Social engineering attacks'
  },
  {
    id: 5,
    name: 'Threat Analysis',
    status: 'available',
    icon: Brain, // Using Brain icon. If not available, BarChartBig would be the alternative.
    path: '/attacks/threat-analysis',
    description: 'Analyze threat patterns and history'
  }
];

const threatFeeds = [
  { id: 1, name: 'MITRE ATT&CK', status: 'active', icon: Shield, path: "/threats/mitre", badge:1 },
  { id: 2, name: 'OSINT Feed', status: 'active', icon: Globe,path: "/threats/osint", badge: 3 },
  { id: 3, name: 'Threat Intel', status: 'warning', icon: AlertOctagon, path: "/threats/intel",badge:2 },
  { id: 4, name: 'CVE Database', status: 'active', icon: Activity, path: "/threats/cve", badge: 4  },
];

const Sidebar = () => {
  const location = useLocation();


    const [systemInfo, setSystemInfo] = useState<any[]>();
  
    useEffect(() => {
      (
        async () => {
          try {
            const info = await axios.get("http://127.0.0.1:8000/api/system/system_info");
            // const info = await axios.get("https://ecyber-backend.onrender.com/api/system/system_info");
            if (info.data) {
              setSystemInfo(info.data);
  
            }
          } catch (error: any) {
            console.error("Error getting system info: ", error)
          }
        }
      )();
    }, []);

  return (
    <SidebarProvider defaultOpen={true}>
      <ShadcnSidebar className="bg-sidebar border-r border-sidebar-border z-20">
        <SidebarHeader className="p-0">
          <div className="flex items-center justify-between p-4 border-b border-sidebar-border">
            <Link to={"/"}>
            <div className="flex items-center space-x-2">
              <div className="w-8 h-8 rounded-md bg-isimbi-purple flex items-center justify-center">
                <span className="text-white font-bold">EC.</span>
              </div>
              <span className="text-lg font-semibold text-white tracking-wider">eCyber</span>
            </div>
            </Link>
          </div>
        </SidebarHeader>
        
        <SidebarContent className="px-0 py-4">
          <SidebarMenu>
            {navItems.map((item) => (
              <SidebarMenuItem key={item.path}>
                <SidebarMenuButton
                  isActive={location.pathname === item.path}
                  tooltip={item.label}
                  asChild
                  className={cn(
                    item.highlight && "bg-isimbi-purple/10 hover:bg-isimbi-purple/20"
                  )}
                >
                  <Link to={item.path} className="flex w-full items-center justify-between">
                    <div className="flex items-center">
                      <item.icon className={cn(
                        "mr-2",
                        item.highlight && "text-isimbi-purple"
                      )} size={20} />
                      <span>{item.label}</span>
                    </div>
                    {item.badge && (
                      <Badge 
                        variant="outline" 
                        className={cn(
                          "ml-2 h-5 min-w-5",
                          item.badge.severity === 'critical' && "border-red-500 text-red-500 bg-red-500/10",
                          item.badge.severity === 'warning' && "border-amber-500 text-amber-500 bg-amber-500/10",
                          item.badge.severity === 'info' && "border-blue-500 text-blue-500 bg-blue-500/10"
                        )}
                      >
                        {item.badge.count}
                      </Badge>
                    )}
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            ))}
          </SidebarMenu>
          
          <SidebarSeparator className="my-4" />
          
          {/* Attack Simulations Section */}
          <SidebarGroup>
            <SidebarGroupLabel className="px-4 flex items-center">
              <ShieldAlert size={14} className="mr-1 text-isimbi-purple" />
              ATTACKS
              <Badge variant="outline" className="ml-2 bg-isimbi-purple/20 border-isimbi-purple text-isimbi-purple text-[10px] h-4 px-1">
                INTERACTIVE
              </Badge>
            </SidebarGroupLabel>
            
            <div className="space-y-1 px-2 mt-1">
              {attackSimulations.map((sim) => (
                <TooltipProvider key={sim.id} delayDuration={300}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Link to={sim.path} className="flex items-center justify-between p-2 rounded-md text-xs hover:bg-white/5 cursor-pointer group">
                        <div className="flex items-center">
                          <div className="w-6 h-6 rounded-full bg-isimbi-purple/10 flex items-center justify-center mr-2">
                            <sim.icon size={14} className="text-isimbi-purple" />
                          </div>
                          <div>
                            <div className="font-medium">{sim.name}</div>
                            <div className="text-[10px] text-muted-foreground">{sim.description}</div>
                          </div>
                        </div>
                        <div className="opacity-0 group-hover:opacity-100 transition-opacity">
                          <Badge variant="outline" className="bg-isimbi-purple/10 border-isimbi-purple/50 text-isimbi-purple text-[10px]">
                            Run
                          </Badge>
                        </div>
                      </Link>
                    </TooltipTrigger>
                    <TooltipContent side="right" className="w-60 p-2">
                      <div className="space-y-1">
                        <h4 className="font-medium text-sm">{sim.name} Attack</h4>
                        <p className="text-xs text-muted-foreground">{sim.description}</p>
                        <div className="flex items-center pt-1">
                          <div className="w-2 h-2 rounded-full bg-green-500 mr-1.5"></div>
                          <span className="text-xs text-green-500">Ready to run</span>
                        </div>
                      </div>
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              ))}
            </div>
          </SidebarGroup>

          <SidebarSeparator className="my-4" />
          
          <div className="px-4 mb-2">
            <h3 className="text-xs font-medium text-muted-foreground mb-2 flex items-center">
              <Bell size={14} className="mr-1" />
              THREAT FEEDS
              <Badge variant="outline" className="ml-2 bg-isimbi-purple/20 border-isimbi-purple text-isimbi-purple text-[10px] h-4 px-1">
                LIVE
              </Badge>
            </h3>
            
            <div className="space-y-1.5">
              {threatFeeds.map((feed) => (
                <TooltipProvider key={feed.id} delayDuration={300}>
                  <Link to={feed.path}>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <div 
                        className={cn(
                          "flex items-center justify-between p-2 rounded-md text-xs hover:bg-white/5 cursor-pointer group",
                          feed.status === 'warning' && "bg-amber-500/5"
                        )}
                      >
                        <div className="flex items-center">
                          <feed.icon size={14} className="mr-2" />
                          <span>{feed.name}</span>
                        </div>
                        <div className="flex items-center">
                          <div 
                            className={cn(
                              "w-2 h-2 rounded-full",
                              feed.status === 'active' ? "bg-green-500" : "bg-amber-500 animate-pulse"
                            )}
                          />
                        </div>
                      </div>
                    </TooltipTrigger>
                    <TooltipContent side="right">
                      <p>{feed.status === 'active' ? 'Feed is active and synced' : 'Warning: Feed has outdated data'}</p>
                    </TooltipContent>
                  </Tooltip>
                  </Link>
                </TooltipProvider>
              ))}
            </div>
          </div>
          
          <SidebarSeparator className="my-4" />
          
          <div className="px-4">
            <h3 className="text-xs font-medium text-muted-foreground mb-2 flex items-center">
              <Zap size={14} className="mr-1" />
              SYSTEM STATUS
            </h3>
            <div className="space-y-2">
              {systemInfo && (
                <>
                  <div className="flex items-center justify-between text-xs p-2">
                      <span className="text-muted-foreground">CPU Load</span>
                      <span className="text-white">{systemInfo?.cpu?.percent}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-green-500 rounded-full"
                        style={{ width: `${systemInfo?.cpu?.percent}%` }}
                      ></div>
                    </div>
          
                    <div className="flex items-center justify-between text-xs p-2">
                      <span className="text-muted-foreground">Memory</span>
                      <span className="text-white">{systemInfo?.memory?.percent}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-amber-500 rounded-full"
                        style={{ width: `${systemInfo.memory.percent}%` }}
                      ></div>
                    </div>
          
                    <div className="flex items-center justify-between text-xs p-2">
                      <span className="text-muted-foreground">Disk</span>
                      <span className="text-white">{systemInfo?.disk.percent?.toFixed(1)}%</span>
                    </div>
                    <div className="w-full h-1.5 bg-white/10 rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-blue-500 rounded-full"
                        style={{ width: `${systemInfo?.disk?.percent}%` }}
                      ></div>
                    </div>
                  </>
                )}
                {!systemInfo && (
                  <p className="text-xs text-muted-foreground">Loading system info...</p>
                )}
              </div>
            </div>
        </SidebarContent>
        
        <SidebarFooter>
          <div className="p-4 border-t border-sidebar-border">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span className="text-xs text-sidebar-foreground/70">System Online</span>
              </div>
              <Badge variant="outline" className="text-xs border-isimbi-purple text-isimbi-purple">
                v1.0.0
              </Badge>
            </div>
          </div>
        </SidebarFooter>
      </ShadcnSidebar>
    </SidebarProvider>
  );
};

export default Sidebar;