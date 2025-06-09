
import React from "react";
import { Layout } from "./Layout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Shield, Eye, AlertTriangle, Globe, MapPin } from "lucide-react";

export function ThreatIntel() {
  return (
    <>
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Threat Intelligence Feed</h1>
        <p className="text-white/60">Comprehensive threat intelligence from premium sources</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
        <Card className="card-glass border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">PREMIUM SOURCES</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline">
              <span className="text-3xl font-bold">7</span>
              <span className="ml-2 text-white/60">Active feeds</span>
            </div>
          </CardContent>
        </Card>
        <Card className="card-glass border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">INDICATORS</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline">
              <span className="text-3xl font-bold">432K</span>
              <span className="ml-2 text-white/60">Total IOCs</span>
            </div>
          </CardContent>
        </Card>
        <Card className="card-glass border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">THREATS DETECTED</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline">
              <span className="text-3xl font-bold">18</span>
              <span className="ml-2 text-white/60">Last 24 hours</span>
            </div>
          </CardContent>
        </Card>
        <Card className="card-glass border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">UPDATES</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-baseline">
              <span className="text-3xl font-bold">5m</span>
              <span className="ml-2 text-white/60">Last refresh</span>
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div className="lg:col-span-2">
          <Card className="card-glass border-white/10 h-full">
            <CardHeader>
              <CardTitle className="flex items-center">
                <Globe className="mr-2 h-5 w-5" />
                Threat Activity Map
              </CardTitle>
              <CardDescription>Global threat activity in the last 24 hours</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="h-[300px] flex items-center justify-center bg-white/5 rounded-md mb-4 relative">
                <div className="absolute inset-0 opacity-40">
                  <div className="w-full h-full bg-[url('/network-bg.svg')] bg-cover bg-center"></div>
                </div>
                <div className="text-center">
                  <p className="text-white/70">Interactive threat map visualization would appear here</p>
                  <p className="text-sm text-white/50 mt-2">Showing real-time attack origins and targets</p>
                </div>
                {/* Sample threat indicators on the map */}
                <div className="absolute top-1/4 left-1/4 w-2 h-2 bg-red-500 rounded-full animate-ping"></div>
                <div className="absolute top-1/3 right-1/3 w-2 h-2 bg-amber-500 rounded-full animate-ping"></div>
                <div className="absolute bottom-1/4 right-1/4 w-2 h-2 bg-red-500 rounded-full animate-ping"></div>
              </div>
              <div className="flex justify-between text-sm">
                <div className="flex items-center">
                  <div className="w-3 h-3 rounded-full bg-red-500 mr-2"></div>
                  <span>Attack Source</span>
                </div>
                <div className="flex items-center">
                  <div className="w-3 h-3 rounded-full bg-amber-500 mr-2"></div>
                  <span>Target</span>
                </div>
                <div className="flex items-center">
                  <div className="w-3 h-3 rounded-full bg-green-500 mr-2"></div>
                  <span>Blocked Attack</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        <Card className="card-glass border-white/10">
          <CardHeader>
            <CardTitle className="flex items-center">
              <AlertTriangle className="mr-2 h-5 w-5" />
              Active Campaigns
            </CardTitle>
            <CardDescription>Current threat campaigns</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                { name: "Operation ShadowHammer", type: "APT", severity: "Critical", indicator: "12 IOCs detected" },
                { name: "DarkHydrus Phishing", type: "Phishing", severity: "High", indicator: "Active in your region" },
                { name: "RansomCartel", type: "Ransomware", severity: "Critical", indicator: "Targeting your industry" },
                { name: "LazarusGroup", type: "APT", severity: "Medium", indicator: "New TTPs identified" },
                { name: "CloudHopper", type: "APT", severity: "High", indicator: "5 IOCs detected" },
              ].map((campaign, index) => (
                <div key={index} className="flex items-start space-x-3 p-3 bg-white/5 rounded-md">
                  <div className={`rounded-full h-2 w-2 mt-2 ${
                    campaign.severity === "Critical" ? "bg-red-500" :
                    campaign.severity === "High" ? "bg-amber-500" :
                    "bg-blue-500"
                  }`}></div>
                  <div>
                    <div className="font-medium">{campaign.name}</div>
                    <div className="flex text-sm text-white/70 mt-1">
                      <span className="mr-2">{campaign.type}</span>
                      <span className="px-1 rounded text-xs bg-white/10">{campaign.severity}</span>
                    </div>
                    <div className="text-xs text-white/60 mt-1">{campaign.indicator}</div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="card-glass border-white/10">
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle className="flex items-center">
              <Eye className="mr-2 h-5 w-5" />
              Threat Intelligence Feed
            </CardTitle>
            <CardDescription>Latest intelligence from premium sources</CardDescription>
          </div>
          <div className="flex space-x-2">
            <button className="text-sm bg-white/10 hover:bg-white/20 px-3 py-1 rounded-md">Filter</button>
            <button className="text-sm bg-white/10 hover:bg-white/20 px-3 py-1 rounded-md">Export</button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {[
              {
                title: "APT-29 New Campaign",
                description: "Russian state-sponsored threat actor APT-29 has been observed using a new strain of malware targeting diplomatic entities.",
                source: "FireEye",
                confidence: "High",
                tags: ["APT", "Russia", "Malware"]
              },
              {
                title: "Zero-day in Popular CMS",
                description: "Active exploitation of a zero-day vulnerability in a popular content management system allows remote code execution.",
                source: "Mandiant",
                confidence: "Critical",
                tags: ["Zero-day", "Web", "RCE"]
              },
              {
                title: "Ransomware-as-a-Service Evolution",
                description: "A new Ransomware-as-a-Service operation has emerged with enhanced encryption and data exfiltration capabilities.",
                source: "CrowdStrike",
                confidence: "Medium",
                tags: ["Ransomware", "RaaS"]
              },
              {
                title: "Supply Chain Compromise",
                description: "A widely-used development library has been compromised to distribute malware to developers.",
                source: "Recorded Future",
                confidence: "High",
                tags: ["Supply Chain", "Developer"]
              }
            ].map((intel, index) => (
              <div key={index} className="border-b border-white/10 pb-4 last:border-0 last:pb-0">
                <div className="flex justify-between mb-1">
                  <h3 className="font-medium">{intel.title}</h3>
                  <span className={`text-xs px-2 py-1 rounded ${
                    intel.confidence === "Critical" ? "bg-red-500/20 text-red-400" :
                    intel.confidence === "High" ? "bg-amber-500/20 text-amber-400" :
                    "bg-blue-500/20 text-blue-400"
                  }`}>{intel.confidence}</span>
                </div>
                <p className="text-sm text-white/70 mb-2">{intel.description}</p>
                <div className="flex items-center justify-between">
                  <div className="flex">
                    {intel.tags.map((tag, i) => (
                      <span key={i} className="mr-1 text-xs bg-white/10 px-2 py-0.5 rounded">{tag}</span>
                    ))}
                  </div>
                  <div className="text-xs text-white/60">Source: {intel.source}</div>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </>
  );
}
