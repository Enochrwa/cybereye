
import React from "react";
import DataTable from "./DataTable";
import { PhishingDetection } from "@/types";

interface PhishingDetectionsTableProps {
  detections: PhishingDetection[];
  className?: string;
}

const PhishingDetectionsTable = ({ detections, className }: PhishingDetectionsTableProps) => {
  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const columns = [
    {
      key: "url",
      header: "Detected URL",
      cell: (detection: PhishingDetection) => (
        <span className="text-xs font-mono break-all">{detection.url}</span>
      ),
      sortable: true,
    },
    {
      key: "confidenceScore",
      header: "Confidence Score",
      cell: (detection: PhishingDetection) => (
        <div className="flex items-center">
          <div className="h-2 w-full max-w-24 bg-muted rounded-full overflow-hidden mr-2">
            <div 
              className="h-full bg-threat-high" 
              style={{ width: `${detection.confidenceScore}%` }}
            />
          </div>
          <span className="text-xs">{detection.confidenceScore.toFixed(1)}%</span>
        </div>
      ),
      sortable: true,
    },
    {
      key: "categories",
      header: "Categories",
      cell: (detection: PhishingDetection) => (
        <div className="flex flex-wrap gap-1">
          {detection.categories.map((category, index) => {
            let bgClass = "bg-muted";
            let textClass = "text-foreground";
            
            if (category === "Phishing") {
              bgClass = "bg-threat-high/10";
              textClass = "text-threat-high";
            } else if (category === "Malware") {
              bgClass = "bg-threat-critical/10";
              textClass = "text-threat-critical";
            } else if (category === "Scam") {
              bgClass = "bg-threat-medium/10";
              textClass = "text-threat-medium";
            }
            
            return (
              <span 
                key={index} 
                className={`${bgClass} ${textClass} px-1.5 py-0.5 rounded text-xs`}
              >
                {category}
              </span>
            );
          })}
        </div>
      ),
    },
    {
      key: "clickThroughRate",
      header: "Click-Through Rate",
      cell: (detection: PhishingDetection) => (
        <span>
          {detection.clickThroughRate !== null 
            ? `${(detection.clickThroughRate * 100).toFixed(1)}%` 
            : "N/A"}
        </span>
      ),
      sortable: true,
    },
    {
      key: "detectionSource",
      header: "Detection Source",
      cell: (detection: PhishingDetection) => (
        <span className={`inline-flex px-2 py-1 rounded-full text-xs ${
          detection.detectionSource === "Automated"
            ? "bg-primary/10 text-primary" 
            : "bg-accent/80 text-accent-foreground"
        }`}>
          {detection.detectionSource}
        </span>
      ),
      sortable: true,
    },
    {
      key: "timestamp",
      header: "Timestamp",
      cell: (detection: PhishingDetection) => (
        <span>{formatTimestamp(detection.timestamp)}</span>
      ),
      sortable: true,
    },
  ];

  return (
    <DataTable columns={columns} data={detections} className={className} />
  );
};

export default PhishingDetectionsTable;
