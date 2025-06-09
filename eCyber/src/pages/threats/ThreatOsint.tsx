
import React from "react";
import { Layout } from "./Layout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Shield, ExternalLink, AlertTriangle, Clock } from "lucide-react";

export function ThreatOsint() {
  return (
    <>
      <div className="mb-6">
        <h1 className="text-2xl font-bold">OSINT Threat Feed</h1>
        <p className="text-white/60">Open Source Intelligence threat data from various sources</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <Card className="card-glass border-white/10">
          <CardHeader>
            <CardTitle className="flex items-center text-lg">
              <Shield className="mr-2 h-5 w-5" />
              Active Sources
            </CardTitle>
            <CardDescription>Connected OSINT feeds</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                  <span>AlienVault OTX</span>
                </div>
                <span className="text-sm text-white/60">24,543 IOCs</span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                  <span>SANS ISC</span>
                </div>
                <span className="text-sm text-white/60">12,876 IOCs</span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-amber-500 rounded-full mr-2"></div>
                  <span>PhishTank</span>
                </div>
                <span className="text-sm text-white/60">8,321 IOCs</span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-red-500 rounded-full mr-2"></div>
                  <span>URLhaus</span>
                </div>
                <span className="text-sm text-white/60">Connection error</span>
              </div>
              <div className="flex items-center justify-between">
                <div className="flex items-center">
                  <div className="w-2 h-2 bg-green-500 rounded-full mr-2"></div>
                  <span>VirusTotal</span>
                </div>
                <span className="text-sm text-white/60">31,209 IOCs</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="card-glass border-white/10">
          <CardHeader>
            <CardTitle className="flex items-center text-lg">
              <Clock className="mr-2 h-5 w-5" />
              Last 24 Hours
            </CardTitle>
            <CardDescription>Recent intelligence</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span>New malicious IPs</span>
                <span className="font-medium">342</span>
              </div>
              <div className="flex items-center justify-between">
                <span>New malicious domains</span>
                <span className="font-medium">187</span>
              </div>
              <div className="flex items-center justify-between">
                <span>New phishing URLs</span>
                <span className="font-medium">93</span>
              </div>
              <div className="flex items-center justify-between">
                <span>New malware hashes</span>
                <span className="font-medium">256</span>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="card-glass border-white/10">
          <CardHeader>
            <CardTitle className="flex items-center text-lg">
              <AlertTriangle className="mr-2 h-5 w-5" />
              Critical Threats
            </CardTitle>
            <CardDescription>High priority intelligence</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-md">
                <div className="font-medium mb-1">Ransomware C2 Servers</div>
                <div className="text-sm text-white/70">12 new C2 servers identified for BlackMatter ransomware variant</div>
              </div>
              <div className="p-3 bg-amber-500/10 border border-amber-500/20 rounded-md">
                <div className="font-medium mb-1">Critical 0-day Exploit</div>
                <div className="text-sm text-white/70">Active exploitation of CVE-2023-XXXX in the wild</div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card className="card-glass border-white/10">
        <CardHeader>
          <CardTitle>Recent OSINT Intelligence</CardTitle>
          <CardDescription>Latest threat indicators from open sources</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="overflow-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left py-2 font-medium">Type</th>
                  <th className="text-left py-2 font-medium">Indicator</th>
                  <th className="text-left py-2 font-medium">Source</th>
                  <th className="text-left py-2 font-medium">Confidence</th>
                  <th className="text-left py-2 font-medium">First Seen</th>
                  <th className="text-left py-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { type: "IP", value: "103.45.232.117", source: "AlienVault", confidence: "High", firstSeen: "2023-05-10" },
                  { type: "Domain", value: "malicious-cdn4.example.net", source: "URLhaus", confidence: "Medium", firstSeen: "2023-05-10" },
                  { type: "URL", value: "hxxp://phish.example.org/login", source: "PhishTank", confidence: "High", firstSeen: "2023-05-09" },
                  { type: "Hash", value: "a1b2c3d4e5f6...", source: "VirusTotal", confidence: "High", firstSeen: "2023-05-09" },
                  { type: "IP", value: "45.77.123.18", source: "AlienVault", confidence: "Medium", firstSeen: "2023-05-09" },
                ].map((item, i) => (
                  <tr key={i} className="border-b border-white/5 hover:bg-white/5">
                    <td className="py-2">{item.type}</td>
                    <td className="py-2 font-mono text-sm">{item.value}</td>
                    <td className="py-2">{item.source}</td>
                    <td className="py-2">
                      <span className={`inline-block px-2 py-1 rounded-full text-xs ${
                        item.confidence === "High" ? "bg-red-500/20 text-red-400" :
                        item.confidence === "Medium" ? "bg-amber-500/20 text-amber-400" :
                        "bg-green-500/20 text-green-400"
                      }`}>{item.confidence}</span>
                    </td>
                    <td className="py-2 text-sm text-white/70">{item.firstSeen}</td>
                    <td className="py-2">
                      <button className="text-cyan-400 hover:text-cyan-300 mr-2">Block</button>
                      <button className="text-cyan-400 hover:text-cyan-300">
                        <ExternalLink className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </>
  );
}
