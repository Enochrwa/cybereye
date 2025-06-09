
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Database, Code, AlertTriangle } from 'lucide-react';
import { SimulationAlert } from '@/components/common/ai-assistant/types';

const SQL_INJECTION_PATTERNS = [
  "' OR '1'='1",
  "'; DROP TABLE users; --",
  "' UNION SELECT * FROM users; --",
  "' OR 1=1; --",
  "admin'--",
  "1' OR '1' = '1",
  "1; DROP TABLE users",
  "' OR ''='",
];

const SQLInjectionSimulation = () => {
  const [input, setInput] = useState('');
  const [attackDetected, setAttackDetected] = useState(false);
  const [alert, setAlert] = useState<SimulationAlert | null>(null);
  const [queryResult, setQueryResult] = useState<string | null>(null);
  
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setInput(e.target.value);
    
    // Reset detection when input changes
    if (attackDetected) {
      setAttackDetected(false);
      setAlert(null);
      setQueryResult(null);
    }
  };
  
  const checkInjection = () => {
    // Check if the input contains any SQL injection patterns
    const containsInjection = SQL_INJECTION_PATTERNS.some(pattern => 
      input.toLowerCase().includes(pattern.toLowerCase())
    );
    
    // Check for other common SQL injection indicators
    const additionalCheck = 
      /(\b(select|insert|update|delete|drop|alter|create|truncate)\b.*\b(from|into|table|database)\b)/i.test(input) ||
      /('|--|#|\/\*|\*\/|;)/i.test(input);
    
    if (containsInjection || additionalCheck || Math.random() > 0.7) {
      setAttackDetected(true);
      setQueryResult('Error: Database query failed');
      
      const severity = containsInjection ? 'critical' : 'warning';
      const pattern = SQL_INJECTION_PATTERNS.find(pattern => 
        input.toLowerCase().includes(pattern.toLowerCase())
      ) || 'Custom SQL pattern';
      
      setAlert({
        id: `sql-${Date.now()}`,
        type: 'sql-injection',
        message: 'SQL Injection attempt detected',
        severity,
        timestamp: new Date(),
        details: {
          pattern,
          input,
          affectedSystem: 'Authentication Database',
          riskLevel: severity === 'critical' ? 'High' : 'Medium',
          signatureID: `SQL-INJ-${Math.floor(Math.random() * 10000)}`
        }
      });
    } else {
      setAttackDetected(false);
      setAlert(null);
      setQueryResult('Query executed: No results returned');
    }
  };
  
  const resetForm = () => {
    setInput('');
    setAttackDetected(false);
    setAlert(null);
    setQueryResult(null);
  };

  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader className="bg-gradient-to-r from-isimbi-navy to-isimbi-dark-charcoal">
        <div className="flex justify-between items-center">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Database className="h-5 w-5 text-isimbi-purple" />
              SQL Injection
            </CardTitle>
            <CardDescription>Simulate SQL injection attacks and detection mechanisms</CardDescription>
          </div>
          <Badge variant={attackDetected ? "destructive" : "outline"} className="ml-2">
            {attackDetected ? "DETECTED" : "Ready"}
          </Badge>
        </div>
      </CardHeader>
      
      <CardContent className="p-6">
        <div className="mb-6">
          <form onSubmit={(e) => { e.preventDefault(); checkInjection(); }} className="space-y-4">
            <div>
              <label htmlFor="sql-input" className="block text-sm font-medium mb-2">
                Username or Search Query
              </label>
              <div className="flex gap-2">
                <Input
                  id="sql-input"
                  value={input}
                  onChange={handleInputChange}
                  placeholder="Enter username or query (try: admin' OR '1'='1)"
                  className="font-mono text-sm"
                />
                <Button type="submit" variant="default">
                  Submit
                </Button>
              </div>
            </div>
          </form>
        </div>
        
        {/* Display SQL injection detection */}
        {attackDetected && (
          <div className="animate-fade-in space-y-4">
            <div className="border border-red-500/20 bg-red-500/10 p-3 rounded-md">
              <div className="flex items-center gap-2 text-red-400 font-semibold text-sm">
                <AlertTriangle className="h-4 w-4" />
                <span>SQL Injection Detected</span>
              </div>
              <div className="mt-2 text-sm text-muted-foreground">
                The input contains potentially malicious SQL commands.
              </div>
            </div>
            
            {queryResult && (
              <div className="bg-secondary p-3 rounded-md font-mono text-xs">
                <div className="text-muted-foreground mb-1">Query Result:</div>
                <div className="text-red-400">{queryResult}</div>
              </div>
            )}
          </div>
        )}
        
        {/* Alert with signature details */}
        {alert && (
          <Alert className={
            alert.severity === 'critical' ? 'mt-4 border-red-500/50 bg-red-500/10' : 'mt-4 border-amber-500/50 bg-amber-500/10'
          }>
            <Code className={
              alert.severity === 'critical' ? 'text-red-500' : 'text-amber-500'
            } />
            <AlertTitle>{alert.message}</AlertTitle>
            <AlertDescription>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-1 mt-2 text-sm">
                <div className="flex items-center gap-1">
                  <span className="text-muted-foreground">Pattern:</span>
                  <span className="font-mono text-xs">{alert.details?.pattern}</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="text-muted-foreground">System:</span>
                  <span>{alert.details?.affectedSystem}</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="text-muted-foreground">Risk:</span>
                  <span>{alert.details?.riskLevel}</span>
                </div>
                <div className="flex items-center gap-1">
                  <span className="text-muted-foreground">Signature:</span>
                  <span className="font-mono text-xs">{alert.details?.signatureID}</span>
                </div>
              </div>
              <div className="mt-3">
                <pre className="bg-secondary p-2 rounded text-xs font-mono overflow-x-auto">
                  {input}
                </pre>
              </div>
            </AlertDescription>
          </Alert>
        )}
        
        {/* SQL injection examples */}
        <div className="mt-6">
          <h3 className="text-sm font-medium mb-2">Example Injection Patterns</h3>
          <div className="flex flex-wrap gap-2">
            {SQL_INJECTION_PATTERNS.slice(0, 5).map((pattern, index) => (
              <Badge 
                key={index} 
                variant="outline" 
                className="cursor-pointer font-mono text-xs"
                onClick={() => setInput(pattern)}
              >
                {pattern}
              </Badge>
            ))}
          </div>
        </div>
      </CardContent>
      
      <CardFooter className="bg-card/50 border-t border-border/50 flex justify-between">
        <div className="text-xs text-muted-foreground">
          Try entering SQL injection patterns to test detection
        </div>
        <Button variant="ghost" size="sm" onClick={resetForm}>
          Reset
        </Button>
      </CardFooter>
    </Card>
  );
};

export default SQLInjectionSimulation;
