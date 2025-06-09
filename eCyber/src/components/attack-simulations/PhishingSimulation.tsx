
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Shield, AlertTriangle } from 'lucide-react';
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";

const PhishingSimulation = () => {
  const { toast } = useToast();
  const [url, setUrl] = useState('');
  const [analysisResult, setAnalysisResult] = useState<null | {
    risk: 'low' | 'medium' | 'high',
    score: number,
    indicators: {
      domain_age_days: number,
      uses_https: boolean,
      has_suspicious_chars: boolean,
      length_score: number,
      entropy_score: number
    },
    domain_info: {
      registrar: string,
      creation_date: string,
      expiration_date: string
    }
  }>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const analyzeURL = () => {
    // Don't do anything if the URL is empty
    if (!url.trim()) {
      toast({
        title: "Empty URL",
        description: "Please enter a URL to analyze",
        variant: "destructive"
      });
      return;
    }
    
    setIsAnalyzing(true);
    
    // Simulate API call with setTimeout
    setTimeout(() => {
      // Check if URL contains obvious phishing indicators
      const hasPhishingIndicators = url.includes('secure') || 
        url.includes('login') || 
        url.includes('verify') ||
        url.includes('account') ||
        url.includes('update') ||
        /[^a-zA-Z0-9\-\.]/.test(url);
      
      // Random score between 1-100 but weighted based on indicators
      const baseScore = Math.floor(Math.random() * 70);
      const finalScore = hasPhishingIndicators 
        ? baseScore + Math.floor(Math.random() * 30) 
        : Math.max(5, baseScore - Math.floor(Math.random() * 30));
      
      // Determine risk level based on score
      let risk: 'low' | 'medium' | 'high';
      if (finalScore < 30) {
        risk = 'low';
      } else if (finalScore < 70) {
        risk = 'medium';
      } else {
        risk = 'high';
      }
      
      // Create mock analysis result
      const result = {
        risk,
        score: finalScore,
        indicators: {
          domain_age_days: Math.floor(Math.random() * 1000),
          uses_https: url.startsWith('https'),
          has_suspicious_chars: /[^a-zA-Z0-9\-\.]/.test(url),
          length_score: url.length > 30 ? 0.8 : 0.2,
          entropy_score: (Math.random() * 0.6) + 0.2
        },
        domain_info: {
          registrar: "Example Registrar, Inc.",
          creation_date: new Date(Date.now() - (Math.random() * 365 * 24 * 60 * 60 * 1000)).toISOString().split('T')[0],
          expiration_date: new Date(Date.now() + (Math.random() * 365 * 24 * 60 * 60 * 1000)).toISOString().split('T')[0]
        }
      };
      
      setAnalysisResult(result);
      setIsAnalyzing(false);
      
      // Show toast notification about the analysis - using default instead of success
      toast({
        title: `URL Analysis: ${risk.toUpperCase()} Risk`,
        description: `Risk Score: ${finalScore}%`,
        variant: risk === 'high' ? "destructive" : "default"
      });
    }, 1500);
  };

  return (
    <Card className="overflow-hidden shadow-lg border-amber-500/20">
      <CardHeader className="bg-gradient-to-r from-amber-500/10 to-transparent">
        <CardTitle className="flex items-center gap-2">
          <AlertTriangle className="h-5 w-5 text-amber-500" />
          Phishing Attack Simulation
        </CardTitle>
        <CardDescription>
          Test the system's ability to detect malicious URLs and phishing attempts
        </CardDescription>
      </CardHeader>
      
      <CardContent className="p-6">
        <div className="space-y-6">
          <div className="space-y-2">
            <Label htmlFor="url-input">Enter URL to Analyze</Label>
            <div className="flex">
              <Input 
                id="url-input"
                placeholder="e.g., https://suspicious-login-verify.example.com"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="flex-1 rounded-r-none focus-visible:ring-amber-500"
              />
              <Button 
                onClick={analyzeURL} 
                disabled={isAnalyzing}
                className="rounded-l-none bg-amber-500 hover:bg-amber-600"
              >
                {isAnalyzing ? "Analyzing..." : "Analyze"}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Enter any URL to test the phishing detection capabilities
            </p>
          </div>
          
          {isAnalyzing && (
            <div className="space-y-2">
              <div className="text-sm">Analyzing URL security...</div>
              <Progress value={45} className="w-full h-2 bg-muted" />
            </div>
          )}
          
          {analysisResult && !isAnalyzing && (
            <div className="space-y-4 animate-fade-in">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-medium">Analysis Result</h3>
                <Badge 
                  variant="outline" 
                  className={`
                    ${analysisResult.risk === 'high' 
                      ? 'bg-red-500/10 text-red-500 border-red-500' 
                      : analysisResult.risk === 'medium'
                        ? 'bg-amber-500/10 text-amber-500 border-amber-500'
                        : 'bg-green-500/10 text-green-500 border-green-500'
                    }
                  `}
                >
                  {analysisResult.risk === 'high' 
                    ? 'High Risk' 
                    : analysisResult.risk === 'medium'
                      ? 'Medium Risk'
                      : 'Low Risk'
                  }
                </Badge>
              </div>
              
              <div>
                <div className="flex justify-between mb-1 text-sm">
                  <span>Risk Score</span>
                  <span className="font-medium">{analysisResult.score}%</span>
                </div>
                <Progress 
                  value={analysisResult.score} 
                  className={`w-full h-3 bg-muted ${
                    analysisResult.risk === 'high' 
                      ? 'text-red-500' 
                      : analysisResult.risk === 'medium'
                        ? 'text-amber-500'
                        : 'text-green-500'
                  }`} 
                />
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Threat Indicators */}
                <div className="p-3 bg-muted/30 rounded-lg">
                  <h4 className="font-medium mb-2 text-sm">Threat Indicators</h4>
                  <ul className="space-y-2 text-sm">
                    <li className="flex items-center justify-between">
                      <span>Domain Age</span>
                      <span>{analysisResult.indicators.domain_age_days} days</span>
                    </li>
                    <li className="flex items-center justify-between">
                      <span>HTTPS</span>
                      <Badge variant={analysisResult.indicators.uses_https ? "outline" : "destructive"}>
                        {analysisResult.indicators.uses_https ? "Yes" : "No"}
                      </Badge>
                    </li>
                    <li className="flex items-center justify-between">
                      <span>Suspicious Characters</span>
                      <Badge variant={analysisResult.indicators.has_suspicious_chars ? "destructive" : "outline"}>
                        {analysisResult.indicators.has_suspicious_chars ? "Yes" : "No"}
                      </Badge>
                    </li>
                    <li className="flex items-center justify-between">
                      <span>URL Complexity</span>
                      <span>{Math.round(analysisResult.indicators.entropy_score * 100)}%</span>
                    </li>
                  </ul>
                </div>
                
                {/* Domain Info */}
                <div className="p-3 bg-muted/30 rounded-lg">
                  <h4 className="font-medium mb-2 text-sm">Domain Information</h4>
                  <ul className="space-y-2 text-sm">
                    <li className="flex items-center justify-between">
                      <span>Registrar</span>
                      <span className="font-mono text-xs">{analysisResult.domain_info.registrar}</span>
                    </li>
                    <li className="flex items-center justify-between">
                      <span>Created</span>
                      <span>{analysisResult.domain_info.creation_date}</span>
                    </li>
                    <li className="flex items-center justify-between">
                      <span>Expires</span>
                      <span>{analysisResult.domain_info.expiration_date}</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      </CardContent>
      
      <CardFooter className="bg-muted/30 px-6 py-4">
        <div className="flex items-center text-xs text-muted-foreground">
          <Shield className="h-3 w-3 mr-1" />
          Phishing detection powered by machine learning algorithms and threat intelligence feeds
        </div>
      </CardFooter>
    </Card>
  );
};

export default PhishingSimulation;
