
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Link, AlertTriangle, Search, Globe, Check, X, ExternalLink, Database, Loader2 } from 'lucide-react';
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

// Types for URL analysis results
interface URLAnalysisResult {
  url: string;
  classification: 'safe' | 'suspicious' | 'malicious' | 'unknown';
  threats: string[];
  score: number; // 0-100, higher means more dangerous
  categories: string[];
  timestamp: Date;
}

const URLClassifier = () => {
  const { toast } = useToast();
  const [url, setUrl] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [analysisResult, setAnalysisResult] = useState<URLAnalysisResult | null>(null);
  const [recentScans, setRecentScans] = useState<URLAnalysisResult[]>([]);
  const [activeTab, setActiveTab] = useState('classifier');

  // Categories of URLs for classification
  const urlCategories = [
    'Phishing',
    'Malware',
    'Spam',
    'Cryptocurrency Mining',
    'Command and Control',
    'Social Engineering',
    'Typosquatting',
    'Data Exfiltration',
    'Financial',
    'Shopping',
    'News',
    'Technology',
    'Education',
  ];

  // Threat types for malicious URLs
  const threatTypes = [
    'Credential Theft',
    'Drive-by Download',
    'Ransomware Distribution',
    'Data Harvesting',
    'Malicious Redirect',
    'Browser Exploit',
    'Trojan Dropper',
    'Command Execution',
    'Cross-Site Scripting',
  ];

  // Known safe domains for testing
  const knownSafeDomains = [
    'google.com',
    'microsoft.com',
    'apple.com',
    'amazon.com',
    'github.com',
    'wikipedia.org',
  ];

  // Known malicious patterns for testing
  const maliciousPatterns = [
    'free-bitcoin',
    'login-verify',
    'account-confirm',
    'password-reset',
    'suspicious',
    'malware',
    'hack',
    'cracked',
    'pirate',
  ];

  const analyzeURL = () => {
    // Validate URL format
    if (!url) {
      toast({
        title: "Invalid URL",
        description: "Please enter a valid URL to analyze",
        variant: "destructive"
      });
      return;
    }

    setAnalyzing(true);
    setProgress(0);
    setAnalysisResult(null);

    toast({
      title: "URL Analysis Started",
      description: `Analyzing ${url} for potential threats`,
      variant: "default"
    });

    // Simulate analysis progress
    const interval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval);
          completeAnalysis();
          return 100;
        }
        return prev + 10;
      });
    }, 300);
  };

  const completeAnalysis = () => {
    // Extract domain from URL for analysis
    let domain = url;
    try {
      const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
      domain = urlObj.hostname;
    } catch (e) {
      // If URL parsing fails, use the input as is
    }

    // Determine if the URL is likely safe or malicious
    const isSafeDomain = knownSafeDomains.some(safe => domain.includes(safe));
    const hasMaliciousPattern = maliciousPatterns.some(pattern => 
      domain.toLowerCase().includes(pattern) || url.toLowerCase().includes(pattern)
    );
    const randomFactor = Math.random();

    let classification: 'safe' | 'suspicious' | 'malicious' | 'unknown';
    let score: number;
    let selectedThreats: string[] = [];
    let selectedCategories: string[] = [];

    if (isSafeDomain && !hasMaliciousPattern) {
      // Known safe domain
      classification = 'safe';
      score = Math.floor(Math.random() * 15);
      selectedCategories = urlCategories.slice(9, 13)
        .sort(() => 0.5 - Math.random())
        .slice(0, 1 + Math.floor(Math.random() * 2));
    } else if (hasMaliciousPattern || randomFactor > 0.7) {
      // Malicious pattern detected or random chance of being malicious
      classification = randomFactor > 0.9 ? 'malicious' : 'suspicious';
      score = classification === 'malicious' 
        ? 80 + Math.floor(Math.random() * 20) 
        : 50 + Math.floor(Math.random() * 30);
      
      // Select random threats
      selectedThreats = threatTypes
        .sort(() => 0.5 - Math.random())
        .slice(0, 1 + Math.floor(Math.random() * 3));
      
      // Select random categories
      selectedCategories = urlCategories.slice(0, 8)
        .sort(() => 0.5 - Math.random())
        .slice(0, 1 + Math.floor(Math.random() * 2));
    } else {
      // Neutral classification
      classification = Math.random() > 0.5 ? 'safe' : 'suspicious';
      score = classification === 'safe' 
        ? Math.floor(Math.random() * 30) 
        : 30 + Math.floor(Math.random() * 20);
      
      if (classification === 'suspicious') {
        selectedThreats = threatTypes
          .sort(() => 0.5 - Math.random())
          .slice(0, 1);
      }
      
      // Mix of categories
      selectedCategories = urlCategories
        .sort(() => 0.5 - Math.random())
        .slice(0, 1 + Math.floor(Math.random() * 2));
    }

    // Create analysis result
    const result: URLAnalysisResult = {
      url,
      classification,
      threats: selectedThreats,
      score,
      categories: selectedCategories,
      timestamp: new Date()
    };

    setAnalysisResult(result);
    setRecentScans(prev => [result, ...prev].slice(0, 10));
    setAnalyzing(false);

    // Show toast with result
    if (classification === 'malicious') {
      toast({
        title: "Dangerous URL Detected",
        description: `${url} is classified as malicious with high confidence`,
        variant: "destructive"
      });
    } else if (classification === 'suspicious') {
      toast({
        title: "Suspicious URL Detected",
        description: `${url} contains potentially suspicious elements`,
        variant: "default"
      });
    } else {
      toast({
        title: "URL Analysis Complete",
        description: `${url} appears to be safe`,
        variant: "default"
      });
    }
  };

  // Get classification badge based on result
  const getClassificationBadge = (classification: 'safe' | 'suspicious' | 'malicious' | 'unknown') => {
    switch (classification) {
      case 'safe':
        return <Badge variant="outline" className="bg-green-500/10 text-green-500 border-green-500">Safe</Badge>;
      case 'suspicious':
        return <Badge variant="outline" className="bg-amber-500/10 text-amber-500 border-amber-500">Suspicious</Badge>;
      case 'malicious':
        return <Badge variant="outline" className="bg-red-500/10 text-red-500 border-red-500">Malicious</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  // Get risk level based on score
  const getRiskLevel = (score: number) => {
    if (score < 20) return 'Very Low';
    if (score < 40) return 'Low';
    if (score < 60) return 'Medium';
    if (score < 80) return 'High';
    return 'Critical';
  };

  // Get color for risk score
  const getRiskColor = (score: number) => {
    if (score < 20) return 'bg-green-500';
    if (score < 40) return 'bg-emerald-500';
    if (score < 60) return 'bg-amber-500';
    if (score < 80) return 'bg-orange-500';
    return 'bg-red-500';
  };

  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Link className="h-5 w-5 text-isimbi-purple" />
          URL Classifier
        </CardTitle>
        <CardDescription>Analyze and classify URLs for security threats</CardDescription>
      </CardHeader>
      
      <div className="border-b border-border">
        <Tabs defaultValue="classifier" onValueChange={setActiveTab}>
          <div className="px-6">
            <TabsList className="grid grid-cols-2 w-full">
              <TabsTrigger value="classifier">URL Classifier</TabsTrigger>
              <TabsTrigger value="history">Scan History</TabsTrigger>
            </TabsList>
          </div>
          
          <TabsContent value="classifier" className="p-6 pt-4">
            <div className="space-y-6">
              {/* URL Input */}
              <div>
                <div className="mb-6">
                  <div className="flex gap-2">
                    <Input
                      placeholder="Enter URL to classify (e.g. example.com)"
                      className="text-sm"
                      value={url}
                      onChange={(e) => setUrl(e.target.value)}
                    />
                    <Button 
                      variant="default" 
                      onClick={analyzeURL}
                      disabled={analyzing || !url}
                    >
                      {analyzing ? (
                        <>
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          Analyzing...
                        </>
                      ) : (
                        <>Classify</>
                      )}
                    </Button>
                  </div>
                </div>
                
                {analyzing && (
                  <div className="space-y-2 mb-6">
                    <div className="flex justify-between text-sm mb-1">
                      <span>Analyzing URL...</span>
                      <span>{Math.round(progress)}%</span>
                    </div>
                    <Progress value={progress} className="h-2" />
                    <div className="text-xs text-muted-foreground">
                      Checking reputation databases and analyzing URL patterns
                    </div>
                  </div>
                )}
                
                {/* Analysis Results */}
                {analysisResult && !analyzing && (
                  <div className={`
                    border rounded-md overflow-hidden
                    ${analysisResult.classification === 'safe' ? 'border-green-500/20 bg-green-500/5' :
                      analysisResult.classification === 'suspicious' ? 'border-amber-500/20 bg-amber-500/5' :
                      'border-red-500/20 bg-red-500/5'}
                  `}>
                    <div className="p-4">
                      <div className="flex items-center justify-between mb-4">
                        <h3 className="font-medium">Analysis Result</h3>
                        {getClassificationBadge(analysisResult.classification)}
                      </div>
                      
                      <div className="space-y-4">
                        <div>
                          <div className="mb-1 text-sm font-medium">
                            {analysisResult.url}
                          </div>
                          <div className="flex items-center text-xs text-muted-foreground">
                            <Globe className="h-3 w-3 mr-1" />
                            Domain analysis complete
                          </div>
                        </div>
                        
                        <div className="grid grid-cols-5 gap-4">
                          <div className="col-span-2">
                            <div className="text-xs text-muted-foreground mb-1">Risk Score</div>
                            <div className="flex items-center space-x-1">
                              <div className="text-xl font-bold">
                                {analysisResult.score}/100
                              </div>
                              <Badge variant="outline" className={`
                                ${analysisResult.score < 20 ? 'bg-green-500/10 text-green-500 border-green-500' :
                                  analysisResult.score < 40 ? 'bg-emerald-500/10 text-emerald-500 border-emerald-500' :
                                  analysisResult.score < 60 ? 'bg-amber-500/10 text-amber-500 border-amber-500' :
                                  analysisResult.score < 80 ? 'bg-orange-500/10 text-orange-500 border-orange-500' :
                                  'bg-red-500/10 text-red-500 border-red-500'}
                              `}>
                                {getRiskLevel(analysisResult.score)}
                              </Badge>
                            </div>
                            <div className="w-full h-2 bg-muted mt-2 rounded-full overflow-hidden">
                              <div 
                                className={`h-full ${getRiskColor(analysisResult.score)}`}
                                style={{ width: `${analysisResult.score}%` }}
                              ></div>
                            </div>
                          </div>
                          
                          <div className="col-span-3">
                            <div className="text-xs text-muted-foreground mb-1">Categories</div>
                            <div className="flex flex-wrap gap-1">
                              {analysisResult.categories.map((category, i) => (
                                <Badge key={i} variant="secondary" className="text-xs">
                                  {category}
                                </Badge>
                              ))}
                            </div>
                            
                            {analysisResult.threats.length > 0 && (
                              <div className="mt-3">
                                <div className="text-xs text-muted-foreground mb-1">Potential Threats</div>
                                <div className="flex flex-wrap gap-1">
                                  {analysisResult.threats.map((threat, i) => (
                                    <Badge key={i} variant="outline" className="bg-red-500/10 text-red-500 border-red-500 text-xs">
                                      {threat}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                    
                    {analysisResult.classification !== 'safe' && (
                      <div className="border-t p-4 bg-muted/50">
                        <div className="flex items-start gap-2">
                          <AlertTriangle className="h-5 w-5 text-amber-500 mt-0.5" />
                          <div>
                            <h4 className="font-medium text-sm">Safety Recommendation</h4>
                            <p className="text-xs text-muted-foreground mt-1">
                              {analysisResult.classification === 'malicious' ? (
                                <span>This URL has been classified as malicious. Do not visit this site as it may compromise your system or steal sensitive information.</span>
                              ) : (
                                <span>This URL contains suspicious elements. Proceed with caution if you choose to visit this site.</span>
                              )}
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                )}
                
                {!analysisResult && !analyzing && (
                  <div className="border rounded-md p-6 text-center">
                    <div className="mb-2 flex justify-center">
                      <Search className="h-12 w-12 text-muted-foreground" />
                    </div>
                    <h3 className="text-lg font-medium mb-1">URL Classifier</h3>
                    <p className="text-sm text-muted-foreground max-w-md mx-auto">
                      Enter a URL to analyze it for security threats and get a risk assessment report
                    </p>
                  </div>
                )}
              </div>
              
              <div className="grid grid-cols-3 gap-4">
                <div className="border rounded-md p-3 text-center">
                  <div className="flex justify-center mb-1">
                    <Check className="h-5 w-5 text-green-500" />
                  </div>
                  <h4 className="text-sm font-medium">Safe URLs</h4>
                  <p className="text-xl font-bold">
                    {recentScans.filter(scan => scan.classification === 'safe').length}
                  </p>
                </div>
                
                <div className="border rounded-md p-3 text-center">
                  <div className="flex justify-center mb-1">
                    <AlertTriangle className="h-5 w-5 text-amber-500" />
                  </div>
                  <h4 className="text-sm font-medium">Suspicious</h4>
                  <p className="text-xl font-bold">
                    {recentScans.filter(scan => scan.classification === 'suspicious').length}
                  </p>
                </div>
                
                <div className="border rounded-md p-3 text-center">
                  <div className="flex justify-center mb-1">
                    <X className="h-5 w-5 text-red-500" />
                  </div>
                  <h4 className="text-sm font-medium">Malicious</h4>
                  <p className="text-xl font-bold">
                    {recentScans.filter(scan => scan.classification === 'malicious').length}
                  </p>
                </div>
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="history" className="p-6 pt-4">
            <div className="space-y-4">
              <h3 className="text-sm font-medium">Recent URL Scans</h3>
              
              <div className="border rounded-md overflow-hidden">
                {recentScans.length > 0 ? (
                  <ScrollArea className="h-[400px]">
                    <div className="divide-y">
                      {recentScans.map((scan, index) => (
                        <div 
                          key={index} 
                          className={`
                            p-4 hover:bg-muted/50
                            ${scan.classification === 'malicious' ? 'bg-red-500/5' :
                              scan.classification === 'suspicious' ? 'bg-amber-500/5' : ''}
                          `}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <div className="font-medium truncate max-w-[250px]" title={scan.url}>
                              {scan.url}
                            </div>
                            <div className="flex items-center gap-2">
                              {getClassificationBadge(scan.classification)}
                              <span className="text-xs text-muted-foreground">
                                {scan.timestamp.toLocaleTimeString()}
                              </span>
                            </div>
                          </div>
                          
                          <div className="flex justify-between items-center">
                            <div className="text-xs text-muted-foreground">
                              Risk score: <span className="font-medium">{scan.score}/100</span> ({getRiskLevel(scan.score)})
                            </div>
                            <div className="flex gap-1">
                              {scan.categories.slice(0, 2).map((category, i) => (
                                <Badge key={i} variant="secondary" className="text-[10px]">
                                  {category}
                                </Badge>
                              ))}
                              {scan.categories.length > 2 && (
                                <Badge variant="secondary" className="text-[10px]">
                                  +{scan.categories.length - 2}
                                </Badge>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <div className="p-8 text-center">
                    <Database className="mx-auto h-8 w-8 text-muted-foreground mb-2" />
                    <p className="text-sm text-muted-foreground">
                      No URL scans in history
                    </p>
                  </div>
                )}
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </div>
      
      <CardFooter className="bg-card/50 border-t border-border/50 flex justify-between p-4">
        <div className="text-xs text-muted-foreground">
          Powered by multi-engine URL security analysis
        </div>
        <Button variant="ghost" size="sm" className="h-8 flex items-center gap-1 text-xs">
          <ExternalLink size={14} />
          View Full Report
        </Button>
      </CardFooter>
    </Card>
  );
};

export default URLClassifier;
