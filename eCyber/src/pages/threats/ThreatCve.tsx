
import React from "react";
import { Layout } from "./Layout";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Shield, Search, AlertTriangle, Calendar, ExternalLink, ArrowUpDown, FileCode } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export function ThreatCve() {
  return (
    <>
      <div className="mb-6">
        <h1 className="text-2xl font-bold">CVE Database</h1>
        <p className="text-white/60">Common Vulnerabilities and Exposures tracking and analysis</p>
      </div>

      <Card className="card-glass border-white/10 mb-6">
        <CardHeader>
          <CardTitle className="flex items-center text-lg">
            <Search className="mr-2 h-5 w-5" />
            Search CVE Database
          </CardTitle>
          <CardDescription>Find vulnerabilities by CVE ID, product, vendor, or keyword</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-2">
              <Input 
                placeholder="Search by CVE ID, product, vendor, or keyword..." 
                className="bg-white/5 border-white/10"
              />
            </div>
            <Select defaultValue="all">
              <SelectTrigger className="bg-white/5 border-white/10">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Button>Search Database</Button>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            <span className="bg-white/10 px-2 py-1 rounded text-xs">CVE-2023-12345</span>
            <span className="bg-white/10 px-2 py-1 rounded text-xs">Log4j</span>
            <span className="bg-white/10 px-2 py-1 rounded text-xs">Microsoft Exchange</span>
            <span className="bg-white/10 px-2 py-1 rounded text-xs">Remote Code Execution</span>
            <span className="bg-white/10 px-2 py-1 rounded text-xs">VMware</span>
            <span className="bg-white/10 px-2 py-1 rounded text-xs">Apache</span>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
        <Card className="card-glass border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center text-lg">
              <AlertTriangle className="mr-2 h-5 w-5 text-red-400" />
              Critical Vulnerabilities
            </CardTitle>
            <CardDescription>High-impact vulnerabilities requiring immediate attention</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {[
                { id: "CVE-2023-12345", name: "Apache Log4j RCE", published: "2023-05-02", cvss: 9.8 },
                { id: "CVE-2023-67890", name: "Microsoft Exchange Server Vuln", published: "2023-05-08", cvss: 9.6 },
                { id: "CVE-2023-54321", name: "OpenSSL Buffer Overflow", published: "2023-05-01", cvss: 9.3 },
              ].map((cve, index) => (
                <div key={index} className="p-3 bg-white/5 rounded-md hover:bg-white/10">
                  <div className="flex justify-between items-start">
                    <div>
                      <div className="font-mono text-sm">{cve.id}</div>
                      <div className="font-medium">{cve.name}</div>
                    </div>
                    <div className="bg-red-500/20 text-red-400 px-2 py-1 rounded text-sm">
                      {cve.cvss}
                    </div>
                  </div>
                  <div className="mt-1 text-sm text-white/60 flex items-center">
                    <Calendar className="h-3 w-3 mr-1" />
                    {cve.published}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="card-glass border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center text-lg">
              <Shield className="mr-2 h-5 w-5" />
              Recently Patched
            </CardTitle>
            <CardDescription>Vulnerabilities with available fixes</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {[
                { id: "CVE-2023-11111", name: "WordPress Plugin Vulnerability", vendor: "WordPress", patchDate: "2023-05-09" },
                { id: "CVE-2023-22222", name: "Cisco IOS XE Software", vendor: "Cisco", patchDate: "2023-05-08" },
                { id: "CVE-2023-33333", name: "VMware vCenter Server", vendor: "VMware", patchDate: "2023-05-07" },
                { id: "CVE-2023-44444", name: "Fortinet FortiOS", vendor: "Fortinet", patchDate: "2023-05-06" },
              ].map((cve, index) => (
                <div key={index} className="p-3 bg-white/5 rounded-md hover:bg-white/10">
                  <div className="flex justify-between">
                    <div className="font-mono text-sm">{cve.id}</div>
                    <div className="bg-green-500/20 text-green-400 px-2 py-0.5 rounded-full text-xs">
                      Patched
                    </div>
                  </div>
                  <div className="font-medium">{cve.name}</div>
                  <div className="mt-1 text-sm text-white/60 flex justify-between">
                    <span>{cve.vendor}</span>
                    <span>Patch: {cve.patchDate}</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="card-glass border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center text-lg">
              <FileCode className="mr-2 h-5 w-5" />
              Exploit Status
            </CardTitle>
            <CardDescription>Vulnerabilities with known exploits</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {[
                { id: "CVE-2023-98765", name: "Chrome Zero-Day", status: "Active Exploitation", severity: "Critical" },
                { id: "CVE-2023-87654", name: "Citrix Gateway RCE", status: "PoC Available", severity: "High" },
                { id: "CVE-2023-76543", name: "F5 BIG-IP", status: "Exploit in Wild", severity: "Critical" },
                { id: "CVE-2023-65432", name: "SAP NetWeaver", status: "Metasploit Module", severity: "High" },
              ].map((cve, index) => (
                <div key={index} className="p-3 bg-white/5 rounded-md hover:bg-white/10">
                  <div className="flex justify-between">
                    <div className="font-mono text-sm">{cve.id}</div>
                    <div className={`px-2 py-0.5 rounded-full text-xs ${
                      cve.severity === "Critical" ? "bg-red-500/20 text-red-400" : 
                      "bg-amber-500/20 text-amber-400"
                    }`}>
                      {cve.severity}
                    </div>
                  </div>
                  <div className="font-medium">{cve.name}</div>
                  <div className="mt-2 text-sm bg-red-500/10 border border-red-500/20 px-2 py-1 rounded">
                    {cve.status}
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
            <CardTitle>CVE Database</CardTitle>
            <CardDescription>Common Vulnerabilities and Exposures database</CardDescription>
          </div>
          <div className="flex space-x-2">
            <Button variant="outline" size="sm">
              <ArrowUpDown className="mr-2 h-4 w-4" />
              Sort
            </Button>
            <Button variant="outline" size="sm">
              Export
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-white/10">
                  <th className="text-left py-3 font-medium">CVE ID</th>
                  <th className="text-left py-3 font-medium">Description</th>
                  <th className="text-left py-3 font-medium">CVSS</th>
                  <th className="text-left py-3 font-medium">Published</th>
                  <th className="text-left py-3 font-medium">Status</th>
                  <th className="text-left py-3 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { id: "CVE-2023-12345", desc: "Remote code execution vulnerability in Apache Log4j", cvss: 9.8, date: "2023-05-02", status: "Patch Available" },
                  { id: "CVE-2023-23456", desc: "Buffer overflow in OpenSSL allows attackers to execute arbitrary code", cvss: 8.4, date: "2023-05-01", status: "Patch Available" },
                  { id: "CVE-2023-34567", desc: "Cross-site scripting vulnerability in WordPress plugin", cvss: 6.3, date: "2023-04-30", status: "Patch Available" },
                  { id: "CVE-2023-45678", desc: "SQL injection vulnerability in CMS platform", cvss: 7.5, date: "2023-04-29", status: "Under Analysis" },
                  { id: "CVE-2023-56789", desc: "Authentication bypass in VPN service", cvss: 8.9, date: "2023-04-28", status: "Exploit Available" },
                ].map((cve, i) => (
                  <tr key={i} className="border-b border-white/5 hover:bg-white/5">
                    <td className="py-3 font-mono">{cve.id}</td>
                    <td className="py-3 max-w-xs truncate">{cve.desc}</td>
                    <td className="py-3">
                      <span className={`inline-block px-2 py-1 rounded text-xs ${
                        cve.cvss >= 9.0 ? "bg-red-500/20 text-red-400" :
                        cve.cvss >= 7.0 ? "bg-amber-500/20 text-amber-400" :
                        cve.cvss >= 4.0 ? "bg-blue-500/20 text-blue-400" :
                        "bg-green-500/20 text-green-400"
                      }`}>{cve.cvss}</span>
                    </td>
                    <td className="py-3 text-sm text-white/70">{cve.date}</td>
                    <td className="py-3">
                      <span className={`inline-block px-2 py-1 rounded-full text-xs ${
                        cve.status === "Exploit Available" ? "bg-red-500/20 text-red-400" :
                        cve.status === "Under Analysis" ? "bg-amber-500/20 text-amber-400" :
                        "bg-green-500/20 text-green-400"
                      }`}>{cve.status}</span>
                    </td>
                    <td className="py-3">
                      <button className="text-cyan-400 hover:text-cyan-300 mr-2">
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
