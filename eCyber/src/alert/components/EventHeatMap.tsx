
import React, { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart";
import { Calendar, Clock } from "lucide-react";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  CartesianGrid,
  Rectangle,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { cn } from "@/lib/utils";

// Type for our heat map data point
interface HeatMapPoint {
  x: number;
  y: number;
  value: number;
  type: string;
}

// Props for our component
interface EventHeatMapProps {
  data: {
    timestamp: string;
    type: string;
  }[];
  className?: string;
}

// Days of week for Y-axis
const DAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

// Time slots for X-axis (24 hours)
const HOURS = Array.from({ length: 24 }, (_, i) => i);

const EventHeatMap = ({ data, className }: EventHeatMapProps) => {
  const [timeRange, setTimeRange] = useState<"day" | "week" | "month">("week");
  const [eventType, setEventType] = useState<string>("all");
  
  // Process data into heat map format
  const processData = (): HeatMapPoint[] => {
    // Filter data by event type if needed
    const filteredData = eventType === "all" 
      ? data 
      : data.filter(item => item.type === eventType);
    
    // Create a map to count occurrences
    const countMap: Record<string, Record<string, { count: number, type: string }>> = {};
    
    // Initialize the map with zeros
    DAYS.forEach(day => {
      countMap[day] = {};
      HOURS.forEach(hour => {
        countMap[day][hour] = { count: 0, type: "" };
      });
    });
    
    // Count events by day of week and hour
    filteredData.forEach(event => {
      const date = new Date(event.timestamp);
      const day = DAYS[date.getDay()];
      const hour = date.getHours();
      
      if (!countMap[day]) countMap[day] = {};
      if (!countMap[day][hour]) countMap[day][hour] = { count: 0, type: event.type };
      
      countMap[day][hour].count += 1;
      countMap[day][hour].type = event.type; // Set to the last type processed (for coloring)
    });
    
    // Convert map to array format for recharts
    const chartData: HeatMapPoint[] = [];
    DAYS.forEach((day, dayIndex) => {
      HOURS.forEach(hour => {
        chartData.push({
          x: hour,
          y: dayIndex,
          value: countMap[day][hour]?.count || 0,
          type: countMap[day][hour]?.type || ""
        });
      });
    });
    
    return chartData;
  };
  
  const chartData = processData();
  
  // Define colors for different event types
  const getEventColor = (type: string, intensity: number): string => {
    // Base color by event type
    const baseColors: Record<string, string> = {
      threat: "#ea384c", // red
      phishing: "#F97316", // orange
      firewall: "#8b5cf6", // purple
      http: "#3b82f6", // blue
      dns: "#EAB308", // yellow
      packet: "#6366f1", // indigo
      response: "#10B981", // green
      quarantine: "#ef4444", // red
      ipv6: "#0ea5e9", // sky blue
      "": "#94a3b8", // gray for unknown
    };
    
    // We'll make the color more transparent for lower intensities
    const alpha = Math.min(0.1 + (intensity * 0.3), 0.9);
    
    // Get the base color or default to gray
    const baseColor = baseColors[type] || baseColors[""];
    
    return intensity === 0 ? "transparent" : `${baseColor}${Math.round(alpha * 255).toString(16).padStart(2, '0')}`;
  };

  // Get the minimum and maximum values for scaling
  const minValue = Math.min(...chartData.map(item => item.value));
  const maxValue = Math.max(...chartData.map(item => item.value));
  
  // Custom shape component for scatter points
  const CustomCell = (props: any) => {
    const { cx, cy, payload } = props;
    
    // Scale for sizing (we want empty cells to still have some size)
    const valueScale = maxValue === 0 ? 0 : payload.value / maxValue;
    const cellSize = 20; // Base cell size
    const padding = 2; // Padding between cells
    const adjustedSize = payload.value === 0 ? cellSize / 2 : cellSize - padding * 2;
    
    return (
      <Rectangle
        x={payload.x * cellSize + padding + (cellSize - adjustedSize) / 2}
        y={payload.y * cellSize + padding + (cellSize - adjustedSize) / 2}
        width={adjustedSize}
        height={adjustedSize}
        fill={getEventColor(payload.type, valueScale)}
        className="transition-all duration-200 hover:opacity-80 cursor-pointer"
      />
    );
  };

  // Get all unique event types for filtering
  const eventTypes = ["all", ...new Set(data.map(item => item.type))];

  return (
    <Card className={cn("overflow-hidden", className)}>
      <CardHeader className="flex flex-row items-center justify-between p-3 sm:p-6">
        <CardTitle className="text-base sm:text-lg font-medium">Security Event Heatmap</CardTitle>
        <div className="flex items-center gap-2 sm:gap-4 flex-wrap">
          <Select value={eventType} onValueChange={(value) => setEventType(value)}>
            <SelectTrigger className="w-[100px] sm:w-[140px] h-8 text-xs sm:text-sm">
              <SelectValue placeholder="Event Type" />
            </SelectTrigger>
            <SelectContent>
              {eventTypes.map(type => (
                <SelectItem key={type} value={type} className="text-xs sm:text-sm">
                  {type === "all" ? "All Events" : type.charAt(0).toUpperCase() + type.slice(1)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Tabs value={timeRange} onValueChange={(v) => setTimeRange(v as "day" | "week" | "month")} className="hidden sm:flex">
            <TabsList>
              <TabsTrigger value="day" className="flex items-center text-xs sm:text-sm">
                <Clock className="w-3 h-3 sm:w-4 sm:h-4 mr-1" />
                Day
              </TabsTrigger>
              <TabsTrigger value="week" className="flex items-center text-xs sm:text-sm">
                <Calendar className="w-3 h-3 sm:w-4 sm:h-4 mr-1" />
                Week
              </TabsTrigger>
              <TabsTrigger value="month" className="flex items-center text-xs sm:text-sm">
                <Calendar className="w-3 h-3 sm:w-4 sm:h-4 mr-1" />
                Month
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </div>
      </CardHeader>
      <CardContent className="p-3 sm:p-6">
        <div className="aspect-[16/10] sm:aspect-[16/8] w-full">
          <ChartContainer config={{}} className="w-full h-full">
            <ResponsiveContainer width="100%" height="100%">
              <ScatterChart
                margin={{
                  top: 20,
                  right: 0,
                  left: 30,
                  bottom: 20,
                }}
              >
                <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                <XAxis
                  type="number"
                  dataKey="x"
                  name="Hour"
                  domain={[0, 23]}
                  tickCount={6}
                  tickFormatter={(hour) => `${hour}:00`}
                  stroke="#94a3b8"
                  tick={{fontSize: 10}}
                />
                <YAxis
                  type="number"
                  dataKey="y"
                  name="Day"
                  tickCount={7}
                  tickFormatter={(index) => DAYS[index].substring(0, 3)}
                  domain={[0, 6]}
                  stroke="#94a3b8"
                  tick={{fontSize: 10}}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload && payload.length) {
                      const data = payload[0].payload;
                      return (
                        <div className="rounded-lg border bg-background p-2 shadow-md text-xs sm:text-sm">
                          <div className="grid grid-cols-2 gap-1 sm:gap-2">
                            <div className="font-medium">Day:</div>
                            <div>{DAYS[data.y]}</div>
                            <div className="font-medium">Time:</div>
                            <div>{`${data.x}:00 - ${data.x + 1}:00`}</div>
                            <div className="font-medium">Events:</div>
                            <div>{data.value}</div>
                            {data.value > 0 && (
                              <>
                                <div className="font-medium">Type:</div>
                                <div className="capitalize">{data.type}</div>
                              </>
                            )}
                          </div>
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <Scatter data={chartData} shape={CustomCell} />
              </ScatterChart>
            </ResponsiveContainer>
          </ChartContainer>
        </div>
        
        <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-2">
          {Object.entries({
            threat: "Threat",
            phishing: "Phishing",
            firewall: "Firewall", 
            http: "HTTP", 
            dns: "DNS", 
            packet: "Packet", 
            response: "Response", 
            quarantine: "Quarantine", 
            ipv6: "IPv6"
          }).map(([key, label]) => (
            <div key={key} className="text-xs flex items-center">
              <span className="inline-block w-3 h-3 rounded mr-1" 
                    style={{ backgroundColor: getEventColor(key, 0.5) }}></span>
              <span>{label}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

export default EventHeatMap;
