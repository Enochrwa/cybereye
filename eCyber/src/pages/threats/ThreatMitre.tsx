
import React from "react";
import { Layout } from "./Layout";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, AlertTriangle, CheckCircle } from "lucide-react";

export function ThreatMitre() {
  return (
    <>
      <div className="mb-6">
        <h1 className="text-2xl font-bold">MITRE ATT&CK Framework</h1>
        <p className="text-white/60">Mapping threats to the MITRE ATT&CK framework for enhanced threat intelligence.</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-6">
        <Card className="card-glass border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg font-medium flex items-center">
              <Shield className="mr-2 h-5 w-5" />
              Initial Access
            </CardTitle>
            <CardDescription>3 techniques detected</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              <li className="flex items-center justify-between">
                <span>T1566 - Phishing</span>
                <AlertTriangle className="h-4 w-4 text-status-warning" />
              </li>
              <li className="flex items-center justify-between">
                <span>T1133 - External Remote Services</span>
                <CheckCircle className="h-4 w-4 text-status-success" />
              </li>
              <li className="flex items-center justify-between">
                <span>T1078 - Valid Accounts</span>
                <AlertTriangle className="h-4 w-4 text-status-warning" />
              </li>
            </ul>
          </CardContent>
        </Card>

        <Card className="card-glass border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg font-medium flex items-center">
              <Shield className="mr-2 h-5 w-5" />
              Execution
            </CardTitle>
            <CardDescription>2 techniques detected</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              <li className="flex items-center justify-between">
                <span>T1059 - Command and Scripting Interpreter</span>
                <AlertTriangle className="h-4 w-4 text-status-critical" />
              </li>
              <li className="flex items-center justify-between">
                <span>T1204 - User Execution</span>
                <CheckCircle className="h-4 w-4 text-status-success" />
              </li>
            </ul>
          </CardContent>
        </Card>

        <Card className="card-glass border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg font-medium flex items-center">
              <Shield className="mr-2 h-5 w-5" />
              Persistence
            </CardTitle>
            <CardDescription>1 technique detected</CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="space-y-2">
              <li className="flex items-center justify-between">
                <span>T1053 - Scheduled Task/Job</span>
                <AlertTriangle className="h-4 w-4 text-status-warning" />
              </li>
            </ul>
          </CardContent>
        </Card>
      </div>

      <Card className="card-glass border-white/10 mb-6">
        <CardHeader className="pb-2">
          <CardTitle className="text-lg font-medium">ATT&CK Matrix Coverage</CardTitle>
          <CardDescription>Coverage of your security controls against the MITRE ATT&CK framework</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-4 md:grid-cols-7 gap-2 text-xs">
            {["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", 
              "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"].map((tactic, index) => (
              <div key={index} className="p-2 bg-white/10 rounded-md hover:bg-white/20 transition-colors text-center">
                {tactic}
              </div>
            ))}
          </div>

          <div className="mt-4 flex justify-between text-sm">
            <div>
              <div className="flex items-center">
                <div className="w-3 h-3 rounded-full bg-status-success mr-2"></div>
                <span>Covered (73%)</span>
              </div>
            </div>
            <div>
              <div className="flex items-center">
                <div className="w-3 h-3 rounded-full bg-status-warning mr-2"></div>
                <span>Partial (18%)</span>
              </div>
            </div>
            <div>
              <div className="flex items-center">
                <div className="w-3 h-3 rounded-full bg-status-critical mr-2"></div>
                <span>At Risk (9%)</span>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="card-glass border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg font-medium">Recent Detections</CardTitle>
            <CardDescription>Mapped to MITRE ATT&CK techniques</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[1, 2, 3].map((_, i) => (
                <div key={i} className="flex items-start border-b border-white/10 pb-2 last:border-0">
                  <div className="mr-3 mt-1">
                    <AlertTriangle className="h-5 w-5 text-status-warning" />
                  </div>
                  <div>
                    <h4 className="font-medium">PowerShell Execution with Encoded Commands</h4>
                    <p className="text-sm text-white/60">T1059.001 - PowerShell</p>
                    <div className="flex mt-1 space-x-4 text-sm">
                      <span>Host: DC01</span>
                      <span>User: admin</span>
                      <span>Time: 14:23:56</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card className="card-glass border-white/10">
          <CardHeader className="pb-2">
            <CardTitle className="text-lg font-medium">Recommended Actions</CardTitle>
            <CardDescription>Based on current threat landscape</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="bg-white/5 p-3 rounded-md">
                <h4 className="font-medium">Update PowerShell Execution Policy</h4>
                <p className="text-sm text-white/60">Restrict PowerShell scripts execution to mitigate T1059.001</p>
                <button className="mt-2 text-sm text-cyan-400 hover:text-cyan-300">View Details</button>
              </div>
              <div className="bg-white/5 p-3 rounded-md">
                <h4 className="font-medium">Enable MFA for External Services</h4>
                <p className="text-sm text-white/60">Add additional layer of security to mitigate T1133</p>
                <button className="mt-2 text-sm text-cyan-400 hover:text-cyan-300">View Details</button>
              </div>
              <div className="bg-white/5 p-3 rounded-md">
                <h4 className="font-medium">Monitor Scheduled Tasks</h4>
                <p className="text-sm text-white/60">Review scheduled tasks for suspicious activities to detect T1053</p>
                <button className="mt-2 text-sm text-cyan-400 hover:text-cyan-300">View Details</button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
