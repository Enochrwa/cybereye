
import { useEffect, useState } from "react";
import { 
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, 
  Legend, ResponsiveContainer 
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { 
  NetworkIOData, DiskIOData, DataPoint
} from "@/lib/socket";

interface ChartsProps {
  cpuHistory: DataPoint[];
  memoryHistory: DataPoint[];
  networkIO: NetworkIOData;
  diskIO: DiskIOData;
}

export function Charts({ cpuHistory, memoryHistory, networkIO, diskIO }: ChartsProps) {
  const [cpuData, setCpuData] = useState<{value: number; timestamp: string}[]>([]);
  const [memoryData, setMemoryData] = useState<{value: number}[]>([]);
  const [networkData, setNetworkData] = useState<{sent: number; received: number; timestamp: string}[]>([]);
  const [diskData, setDiskData] = useState<{read: number; write: number; timestamp: string}[]>([]);

  useEffect(() => {
    // Create data for the charts
    const timestamps = Array.from({ length: cpuHistory.length }, (_, i) => {
      const date = new Date();
      date.setMinutes(date.getMinutes() - (cpuHistory.length - i - 1));
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    });

    // CPU chart data
    setCpuData(cpuHistory.map((point, index) => ({
      value: point.value,
      timestamp: timestamps[index]
    })));

    // Memory chart data
    setMemoryData(memoryHistory.map(point => ({ value: point.value })));

    // Network chart data
    if (networkIO) {
      setNetworkData([{
        sent: networkIO.sent,
        received: networkIO.received,
        timestamp: new Date(networkIO.timestamp).toLocaleTimeString()
      }]);
    }

    // Disk chart data
    if (diskIO) {
      const diskDataArray = [];
      for (let i = 0; i < diskIO.read.length; i++) {
        diskDataArray.push({
          read: diskIO.read[i],
          write: diskIO.write[i],
          timestamp: diskIO.timestamps[i]
        });
      }
      setDiskData(diskDataArray);
    }
  }, [cpuHistory, memoryHistory, networkIO, diskIO]);

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* CPU Usage Chart */}
      <Card className="bg-card">
        <CardHeader className="pb-2">
          <CardTitle className="text-base">CPU Usage (%)</CardTitle>
        </CardHeader>
        <CardContent className="h-[200px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={cpuData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2A3042" />
              <XAxis 
                dataKey="timestamp" 
                tick={{ fontSize: 10, fill: '#9B87F5' }}
                stroke="#3F4C67"
              />
              <YAxis 
                domain={[0, 100]} 
                tick={{ fontSize: 10, fill: '#9B87F5' }}
                stroke="#3F4C67"
              />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1A1F2C', 
                  borderColor: '#3F4C67',
                  color: '#fff'
                }} 
              />
              <Line 
                type="monotone" 
                dataKey="value" 
                stroke="#9B87F5" 
                strokeWidth={2} 
                dot={false}
                activeDot={{ r: 6 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Memory Usage Chart */}
      <Card className="bg-card">
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Memory Usage (%)</CardTitle>
        </CardHeader>
        <CardContent className="h-[200px] flex justify-center items-center">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={[
                  { name: 'Used', value: memoryData.length ? memoryData[memoryData.length - 1].value : 0 },
                  { name: 'Free', value: memoryData.length ? 100 - memoryData[memoryData.length - 1].value : 100 }
                ]}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                fill="#8884d8"
                paddingAngle={5}
                dataKey="value"
              >
                <Cell fill="#9B87F5" />
                <Cell fill="#2A3042" />
              </Pie>
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1A1F2C', 
                  borderColor: '#3F4C67',
                  color: '#fff'
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Network I/O Chart */}
      <Card className="bg-card">
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Network I/O (MB/s)</CardTitle>
        </CardHeader>
        <CardContent className="h-[200px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={networkData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2A3042" />
              <XAxis 
                dataKey="timestamp" 
                tick={{ fontSize: 10, fill: '#9B87F5' }}
                stroke="#3F4C67"
              />
              <YAxis 
                tick={{ fontSize: 10, fill: '#9B87F5' }}
                stroke="#3F4C67"
              />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1A1F2C', 
                  borderColor: '#3F4C67',
                  color: '#fff'
                }}
              />
              <Legend />
              <Area 
                type="monotone" 
                dataKey="sent" 
                stackId="1" 
                stroke="#60A5FA" 
                fill="#60A5FA" 
                fillOpacity={0.6}
              />
              <Area 
                type="monotone" 
                dataKey="received" 
                stackId="1" 
                stroke="#34D399" 
                fill="#34D399" 
                fillOpacity={0.6}
              />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Disk I/O Chart */}
      <Card className="bg-card">
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Disk I/O (MB/s)</CardTitle>
        </CardHeader>
        <CardContent className="h-[200px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={diskData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2A3042" />
              <XAxis 
                dataKey="timestamp" 
                tick={{ fontSize: 10, fill: '#9B87F5' }}
                stroke="#3F4C67"
              />
              <YAxis 
                tick={{ fontSize: 10, fill: '#9B87F5' }}
                stroke="#3F4C67"
              />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1A1F2C', 
                  borderColor: '#3F4C67',
                  color: '#fff'
                }}
              />
              <Legend />
              <Bar dataKey="read" fill="#FBBF24" />
              <Bar dataKey="write" fill="#F87171" />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </div>
  );
}
