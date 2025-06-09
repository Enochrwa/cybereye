
import React, { useState, useEffect } from 'react';
import { 
  HardDrive, Usb, Search, Filter, RefreshCcw, AlertTriangle, 
  X, Check, Laptop
} from 'lucide-react';
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";

// Types for device/peripheral
interface Device {
  id: string;
  name: string;
  type: 'USB' | 'External Drive' | 'Bluetooth' | 'Other';
  mountPath?: string;
  connectedAt: Date;
  isNew: boolean;
  isTrusted: boolean;
  size?: string;
  model?: string;
  serialNumber?: string;
}

const DeviceAccessMonitor = () => {
  const { toast } = useToast();
  const [devices, setDevices] = useState<Device[]>([]);
  const [showUntrustedOnly, setShowUntrustedOnly] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  
  // Generate sample devices
  const generateDevices = (): Device[] => {
    const deviceTypes: ('USB' | 'External Drive' | 'Bluetooth' | 'Other')[] = [
      'USB', 'External Drive', 'USB', 'USB', 'Bluetooth', 'Other'
    ];
    const deviceNames = [
      'Kingston DataTraveler',
      'SanDisk Cruzer',
      'Seagate Backup Plus',
      'WD Elements',
      'Generic USB Device',
      'Logitech Bluetooth Mouse',
      'Apple Magic Keyboard',
      'Samsung T7'
    ];
    
    const devicesCount = Math.floor(Math.random() * 3) + 2; // 2-4 devices
    const devices: Device[] = [];
    
    for (let i = 0; i < devicesCount; i++) {
      const deviceTypeIndex = Math.floor(Math.random() * deviceTypes.length);
      const deviceType = deviceTypes[deviceTypeIndex];
      const deviceName = deviceNames[Math.floor(Math.random() * deviceNames.length)];
      const isNew = Math.random() > 0.7; // 30% chance of being new
      const isTrusted = Math.random() > 0.2; // 80% chance of being trusted
      
      let mountPath;
      let size;
      
      if (deviceType === 'USB' || deviceType === 'External Drive') {
        mountPath = `/media/usb${i}`;
        size = `${Math.floor(Math.random() * 900) + 100} GB`;
      }
      
      devices.push({
        id: `device-${Date.now()}-${i}`,
        name: deviceName,
        type: deviceType,
        mountPath,
        connectedAt: new Date(Date.now() - Math.floor(Math.random() * 86400000)), // Random time in last 24hrs
        isNew,
        isTrusted,
        size,
        model: `Model ${String.fromCharCode(65 + i)}`,
        serialNumber: `SN${Math.floor(Math.random() * 1000000).toString().padStart(6, '0')}`
      });
    }
    
    return devices;
  };
  
  // Initialize devices
  useEffect(() => {
    const devices = generateDevices();
    setDevices(devices);
    
    // Simulate new device connection occasionally
    const interval = setInterval(() => {
      const shouldAddNewDevice = Math.random() > 0.7; // 30% chance
      
      if (shouldAddNewDevice) {
        const newDevice: Device = {
          id: `device-${Date.now()}`,
          name: 'New USB Device',
          type: 'USB',
          mountPath: '/media/usb-new',
          connectedAt: new Date(),
          isNew: true,
          isTrusted: false,
          size: `${Math.floor(Math.random() * 64) + 1} GB`,
          model: 'Unknown',
          serialNumber: `SN${Math.floor(Math.random() * 1000000).toString().padStart(6, '0')}`
        };
        
        setDevices(prev => [...prev, newDevice]);
        
        toast({
          title: "New Device Connected",
          description: `${newDevice.name} connected to system`,
          // Fix: Change "warning" to a valid variant
          variant: "default" 
        });
      }
    }, 15000); // Check every 15 seconds
    
    return () => clearInterval(interval);
  }, [toast]);
  
  // Filter devices
  const filteredDevices = devices.filter(device => {
    const matchesSearch = !searchTerm || 
      device.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      device.type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (device.mountPath && device.mountPath.includes(searchTerm));
    
    return matchesSearch && (!showUntrustedOnly || !device.isTrusted);
  });
  
  // Trust device
  const trustDevice = (deviceId: string) => {
    setDevices(prev => 
      prev.map(device => 
        device.id === deviceId 
          ? { ...device, isTrusted: true, isNew: false } 
          : device
      )
    );
    
    toast({
      title: "Device Trusted",
      description: "Device has been marked as trusted"
    });
  };
  
  // Block device
  const blockDevice = (deviceId: string) => {
    setDevices(prev => prev.filter(device => device.id !== deviceId));
    
    toast({
      title: "Device Blocked",
      description: "Device has been blocked and ejected"
    });
  };
  
  // Eject device
  const ejectDevice = (deviceId: string) => {
    setDevices(prev => prev.filter(device => device.id !== deviceId));
    
    toast({
      title: "Device Ejected",
      description: "Device has been safely ejected"
    });
  };

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium">Device & Peripheral Access</h3>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <input
              type="search"
              placeholder="Search devices..."
              className="pl-8 h-9 w-[220px] rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm transition-colors file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
          </div>
          <Button 
            size="sm" 
            variant={showUntrustedOnly ? "default" : "outline"} 
            className="h-9 gap-1"
            onClick={() => setShowUntrustedOnly(!showUntrustedOnly)}
          >
            <AlertTriangle className="h-4 w-4" />
            {showUntrustedOnly ? "Show All" : "Untrusted Only"}
          </Button>
          <Button size="sm" className="h-9 gap-1" onClick={() => setDevices(generateDevices())}>
            <RefreshCcw className="h-4 w-4" />
            Refresh
          </Button>
        </div>
      </div>
      
      {/* Devices Table */}
      <div className="border rounded-lg overflow-hidden">
        <div className="grid grid-cols-7 gap-2 py-2 px-3 bg-muted text-xs font-medium">
          <div className="col-span-1">Type</div>
          <div className="col-span-2">Name</div>
          <div className="col-span-1">Mount Point</div>
          <div className="col-span-1">Connected At</div>
          <div className="col-span-1">Status</div>
          <div className="col-span-1">Actions</div>
        </div>
        
        <ScrollArea className="h-[400px]">
          {filteredDevices.length > 0 ? (
            <div className="divide-y">
              {filteredDevices.map((device) => (
                <div 
                  key={device.id}
                  className={`grid grid-cols-7 gap-2 py-2 px-3 text-xs ${
                    !device.isTrusted ? 'bg-red-500/5' : 
                    device.isNew ? 'bg-amber-500/5' : ''
                  } hover:bg-muted/50`}
                >
                  <div className="col-span-1">
                    <Badge variant="outline" className={
                      device.type === 'USB' ? 'bg-blue-500/10 text-blue-500 border-blue-500' :
                      device.type === 'External Drive' ? 'bg-green-500/10 text-green-500 border-green-500' :
                      device.type === 'Bluetooth' ? 'bg-purple-500/10 text-purple-500 border-purple-500' :
                      'bg-gray-500/10 text-gray-500 border-gray-500'
                    }>
                      {device.type}
                    </Badge>
                  </div>
                  <div className="col-span-2 flex items-center gap-1">
                    {!device.isTrusted && <AlertTriangle className="h-3 w-3 text-red-500" />}
                    {device.isNew && device.isTrusted && <Laptop className="h-3 w-3 text-amber-500" />}
                    <span className={!device.isTrusted ? 'text-red-500' : device.isNew ? 'text-amber-500' : ''}>
                      {device.name}
                    </span>
                    {device.size && (
                      <span className="text-xs text-muted-foreground ml-1">
                        ({device.size})
                      </span>
                    )}
                  </div>
                  <div className="col-span-1 font-mono">
                    {device.mountPath || '—'}
                  </div>
                  <div className="col-span-1">
                    {device.connectedAt.toLocaleTimeString()}
                  </div>
                  <div className="col-span-1">
                    {device.isNew ? (
                      <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500">
                        New
                      </Badge>
                    ) : device.isTrusted ? (
                      <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500">
                        Trusted
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500">
                        Untrusted
                      </Badge>
                    )}
                  </div>
                  <div className="col-span-1 flex items-center gap-1">
                    {!device.isTrusted ? (
                      <>
                        <Button 
                          variant="ghost" 
                          size="sm" 
                          className="h-6 text-[10px]"
                          onClick={() => trustDevice(device.id)}
                        >
                          <Check className="h-3 w-3 mr-1" />
                          Trust
                        </Button>
                        <Button 
                          variant="destructive" 
                          size="sm" 
                          className="h-6 text-[10px]"
                          onClick={() => blockDevice(device.id)}
                        >
                          <X className="h-3 w-3 mr-1" />
                          Block
                        </Button>
                      </>
                    ) : (
                      <Button 
                        variant="ghost" 
                        size="sm" 
                        className="h-6 text-[10px]"
                        onClick={() => ejectDevice(device.id)}
                      >
                        <HardDrive className="h-3 w-3 mr-1" />
                        Eject
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center text-sm text-muted-foreground">
              No devices connected
            </div>
          )}
        </ScrollArea>
      </div>
      
      {/* Device Stats */}
      <div className="grid grid-cols-4 gap-4">
        <div className="border rounded-md p-3">
          <div className="text-sm font-medium mb-1">Total Devices</div>
          <div className="text-2xl font-bold">{devices.length}</div>
          <div className="text-xs text-muted-foreground mt-1">Connected to system</div>
        </div>
        <div className="border rounded-md p-3">
          <div className="text-sm font-medium mb-1">Trusted Devices</div>
          <div className="text-2xl font-bold text-green-500">{devices.filter(d => d.isTrusted).length}</div>
          <div className="text-xs text-muted-foreground mt-1">Approved for use</div>
        </div>
        <div className="border rounded-md p-3">
          <div className="text-sm font-medium mb-1">New Devices</div>
          <div className="text-2xl font-bold text-amber-500">{devices.filter(d => d.isNew).length}</div>
          <div className="text-xs text-muted-foreground mt-1">Recently connected</div>
        </div>
        <div className="border rounded-md p-3">
          <div className="text-sm font-medium mb-1">Untrusted Devices</div>
          <div className="text-2xl font-bold text-red-500">{devices.filter(d => !d.isTrusted).length}</div>
          <div className="text-xs text-muted-foreground mt-1">Require authorization</div>
        </div>
      </div>
      
      {/* Device Policies */}
      <div className="border rounded-lg p-4">
        <h4 className="text-sm font-medium mb-3">Device Access Policies</h4>
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="text-sm">Auto-block unknown USB devices</div>
            <div className="flex items-center">
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={true} 
                  className="sr-only peer" 
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
              </label>
            </div>
          </div>
          <div className="flex items-center justify-between">
            <div className="text-sm">Block file execution from removable media</div>
            <div className="flex items-center">
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={true} 
                  className="sr-only peer" 
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
              </label>
            </div>
          </div>
          <div className="flex items-center justify-between">
            <div className="text-sm">Automatically scan connected devices</div>
            <div className="flex items-center">
              <label className="relative inline-flex items-center cursor-pointer">
                <input 
                  type="checkbox" 
                  checked={true} 
                  className="sr-only peer" 
                />
                <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-blue-300 dark:peer-focus:ring-blue-800 rounded-full peer dark:bg-gray-700 peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all dark:border-gray-600 peer-checked:bg-blue-600"></div>
              </label>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DeviceAccessMonitor;
