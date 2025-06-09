
import React, { useState, useEffect } from 'react';
import axios from 'axios'
import { cn } from '@/lib/utils';
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import { Cpu, BarChart, PlayCircle, ArrowRight, Zap, StopCircle, RefreshCw, Check, AlertCircle } from 'lucide-react';
import Header from '../components/layout/Header';
import ModelTraining from '../components/models/ModelTraining';
import ModelMetrics from '../components/models/ModelMetrics';
import ModelFilters from '../components/models/ModelFilters';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { useToast } from "@/hooks/use-toast";

// Define the ModelData interface
interface ModelData {
  id: string; // e.g., "Bot_XGBoost"
  name: string; // e.g., "Bot Detection"
  status: 'active' | 'inactive' | 'training'; // Status might be dynamic from backend later
  accuracy: number | null; // From meta.json or calculated
  f1Score?: number | null;
  precision?: number | null;
  recall?: number | null;
  auc?: number | null;
  confusionMatrixData?: Array<{ label: string; values: number[] }> | null;
  lastTrained: string | null; // ISO date string from meta.json or file system
  description: string;
  type: string; // e.g., XGBoost, RandomForest from meta.json
  features?: string[]; // From meta.json
  model_file?: string;
  scaler_file?: string;
  metadata_file?: string;
}

// Sample model insights (to be removed or replaced with dynamic data)
// const modelInsights = [
//   { metric: "Threats detected", value: 28, trend: "up", change: "12%" },
//   { metric: "False positives", value: 3, trend: "down", change: "8%" },
//   { metric: "Processing time", value: "1.2s", trend: "down", change: "5%" },
//   { metric: "Model accuracy", value: "94%", trend: "up", change: "2%" },
// ];

const MODELS_CACHE_KEY = 'models_cache';
const CACHE_FRESHNESS_DURATION = 5 * 60 * 1000; // 5 minutes in milliseconds

const Models = () => {

  const cachedModels = JSON.parse(localStorage.getItem('models_cache'));

  const [models, setModels] = useState<ModelData[]>(cachedModels?.data || []);
  const [insights, setInsights] = useState<any[]>([]); // Placeholder for future dynamic insights
  const [activeModel, setActiveModel] = useState<ModelData | null>(null);
  const [runningModels, setRunningModels] = useState<Record<string, {progress: number, running: boolean}>>({});
  const [showAllMetrics, setShowAllMetrics] = useState(false);
  const [selectedStatuses, setSelectedStatuses] = useState<string[]>(['active', 'training', 'inactive']);
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);
  const { toast } = useToast();
  const [isLoading, setIsLoading] = useState<boolean>(false);
  // const [fetchError, setFetchError] = useState<string | null>(null); // Optional: for displaying specific error messages in UI

  useEffect(() => {
    const fetchModels = async () => {
      setIsLoading(true);
      // Attempt to load from cache first
      try {
        const cachedDataString = localStorage.getItem(MODELS_CACHE_KEY);
        if (cachedDataString) {
          const cachedData = JSON.parse(cachedDataString);
          if (cachedData && cachedData.data && cachedData.timestamp && (Date.now() - cachedData.timestamp < CACHE_FRESHNESS_DURATION)) {
            setModels(cachedData.data);
            setIsLoading(false);
            toast({ title: "Models Loaded", description: "Displaying up-to-date cached model data.", variant: "default" });
            return; // Exit fetchModels as fresh data is loaded
          }
        }
      } catch (e) {
        // If parsing fails, proceed to fetch from API
        console.warn("Failed to parse cached model data or cache is invalid:", e);
        localStorage.removeItem(MODELS_CACHE_KEY); // Clear corrupted cache
      }

      // Original API fetching logic
      try {
        const response = await axios.get("http://127.0.0.1:8000/api/v1/models/list");
        const data: ModelData[] = response.data;
  
        // Save to Cache on Successful Fetch
        localStorage.setItem(MODELS_CACHE_KEY, JSON.stringify({ timestamp: Date.now(), data: data }));
        setModels(data);
      } catch (error:any) {
        !cachedModels.data && console.error("Failed to fetch models:", error?.toString());
        
      } finally {
        setIsLoading(false);
      }
    };

    fetchModels();
  }, [refreshKey, toast]);
  
    // Filter models based on search term and status
    const safeString = (value) => (typeof value === 'string' ? value.toLowerCase() : '');

  const filteredModels = (Array.isArray(models) ? models : []).filter(model => {
    const name = safeString(model?.name);
    const description = safeString(model?.description);
    const type = safeString(model?.type);
    const status = model?.status;

    const search = safeString(searchTerm);
    const matchesSearch = name.includes(search) || description.includes(search) || type.includes(search);

    const matchesStatus = Array.isArray(selectedStatuses) && selectedStatuses.includes(status);

    return matchesSearch && matchesStatus;
  });

  // Sort models based on selected sort option
  const sortedModels = [...filteredModels].sort((a, b) => {
    switch(sortBy) {
      case 'accuracy-high':
        return (b.accuracy || 0) - (a.accuracy || 0);
      case 'accuracy-low':
        return (a.accuracy || 0) - (b.accuracy || 0);
      case 'name-asc':
        return a.name.localeCompare(b.name);
      case 'name-desc':
        return b.name.localeCompare(a.name);
      case 'recent':
        return new Date(b.lastTrained || 0).getTime() - new Date(a.lastTrained || 0).getTime();
      default:
        return 0;
    }
  });
  
  const handleRunModel = (model: ModelData) => {
    if (model.status === "training") {
      toast({
        title: "Model Unavailable",
        description: "This model is currently training and cannot be run",
        variant: "destructive",
      });
      return;
    }
    
    toast({
      title: "Running Model",
      description: `Executing ${model.name} on current data`,
    });
    
    // Set up running state for this model
    setRunningModels(prev => ({
      ...prev,
      [model.id]: { progress: 0, running: true }
    }));
    
    // Simulate progress
    // TODO: Replace with actual model running logic
    const intervalId = setInterval(() => {
      setRunningModels(prev => {
        const modelState = prev[model.id];
        // If model was stopped, clear interval
        if (!modelState?.running) {
            clearInterval(intervalId);
            return prev;
        }
        const currentProgress = modelState?.progress || 0;
        
        if (currentProgress >= 100) {
          clearInterval(intervalId);
          
          // Show completion toast
          toast({
            title: "Model Execution Complete",
            description: `${model.name} analysis completed successfully`,
          });
          
          return {
            ...prev,
            [model.id]: { progress: 100, running: false }
          };
        }
        
        return {
          ...prev,
          [model.id]: { progress: Math.min(currentProgress + 10, 100), running: true }
        };
      });
    }, 300);
  };
  
  const handleStopModel = (model: ModelData) => {
    toast({
      title: "Model Stopped",
      description: `${model.name} execution has been stopped`,
    });
    
    setRunningModels(prev => ({
      ...prev,
      [model.id]: { ...prev[model.id], running: false } // Keep progress but set running to false
    }));
  };
  
  const handleRefreshModels = () => {
    localStorage.removeItem(MODELS_CACHE_KEY); // Clear cache
    toast({
      title: "Refreshing Models",
      description: "Fetching latest model status and metrics...",
    });
    
    setRefreshKey(prev => prev + 1); // Trigger useEffect to call fetchModels
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
    
      
      <main className="flex-1 overflow-auto p-6">
        <div className="max-w-7xl mx-auto">
          {/* Page header */}
          <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
            <div>
              <h1 className="text-2xl font-bold tracking-tight">ML & AI Models</h1>
              <p className="text-muted-foreground">Manage and train AI security models</p>
            </div>
            
            <div className="flex items-center gap-2 mt-4 md:mt-0">
              <div className="text-xs text-muted-foreground flex items-center">
                <span className="mr-1">Last updated:</span>
                <span className="bg-muted/50 px-2 py-1 rounded text-xs">{new Date().toLocaleTimeString()}</span>
              </div>
              <Button 
                variant="outline" 
                size="sm"
                onClick={handleRefreshModels}
                className="ml-2 hover:bg-primary/10" 
              >
                <RefreshCw className="mr-1 h-4 w-4" />
                Refresh
              </Button>
              <Button 
                variant="outline" 
                size="sm" 
                onClick={() => setShowAllMetrics(!showAllMetrics)}
                className={cn(
                  "ml-2",
                  showAllMetrics ? "bg-primary/10 text-primary" : ""
                )}
              >
                {showAllMetrics ? "Hide All Metrics" : "Show All Metrics"}
              </Button>
            </div>
          </div>
          
          {/* Model filters */}
          <ModelFilters 
            onSearch={setSearchTerm}
            onFilterChange={setSortBy}
            onStatusChange={setSelectedStatuses}
            selectedStatuses={selectedStatuses}
          />
          
          {/* Model insights (temporarily removed - to be replaced with dynamic insights) */}
          {/* 
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            {insights.map((insight, index) => ( // Assuming 'insights' state will be populated later
              <Card 
                key={index} 
                className="bg-card/70 backdrop-blur-sm card-hover-subtle animate-fade-in-up"
                style={{ animationDelay: `${index * 0.1}s` }}
              >
                <CardContent className="p-6">
                  <div className="text-muted-foreground text-sm">{insight.metric}</div>
                  <div className="text-2xl font-semibold mt-1">{insight.value}</div>
                  <div className={cn(
                    "text-xs flex items-center mt-2",
                    insight.trend === "up" ? "text-green-500" : "text-blue-500"
                  )}>
                    <span className={cn(
                      "mr-1 text-xs",
                      insight.trend === "up" ? "text-green-500" : "text-blue-500"
                    )}>
                      {insight.trend === "up" ? "↑" : "↓"}
                    </span>
                    {insight.change} from last month
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
          */}
          
          {/* Show All Metrics section conditionally */}
          {showAllMetrics && (
            <div className="mb-6 animate-fade-in-up">
              <Card className="bg-card/70 backdrop-blur-sm card-shine">
                <CardHeader>
                  <CardTitle className="flex items-center">
                    <BarChart className="mr-2" size={18} />
                    All Model Metrics
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-h-[70vh] overflow-y-auto">
                    {models.map((model, index) => ( // Changed from mlModels to models
                      <div 
                        key={model.id} 
                        className="border border-border rounded-xl p-6 bg-gradient-to-br from-card to-muted/5 card-hover animate-fade-in-up "
                        style={{ animationDelay: `${index * 0.15}s` }}
                      >
                        <h3 className="font-medium flex items-center">
                          <Cpu className="h-4 w-4 mr-2 text-primary" />
                          {model.name} Metrics
                        </h3>
                        <div className="mt-2 mb-4">
                          <Badge className={cn(
                            "status-badge",
                            model.status === "active" ? "active" : 
                            model.status === "training" ? "training" : 
                            "inactive"
                          )}>
                            {model.status}
                          </Badge>
                          <span className="ml-2 text-xs text-muted-foreground">Type: {model.type}</span>
                        </div>
                        {/* Pass the full model object to ModelMetrics */}
                        <ModelMetrics model={model} />
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </div>
          )}
          
          {/* Model Training */}
          <div className="mb-6">
            <ModelTraining />
          </div>
          
          {/* Models list */}
          <Card className="bg-card/70 backdrop-blur-sm card-shine">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center">
                  <Cpu className="mr-2" size={18} />
                  ML Models
                  <Badge className="ml-2 bg-primary/20 text-primary">{sortedModels.length}</Badge>
                </div>
                <Dialog>
                  <DialogTrigger asChild>
                    <Button className="bg-primary/10 hover:bg-primary/20">
                      <Zap className="mr-2 h-4 w-4" />
                      View All Models
                    </Button>
                  </DialogTrigger>
                  <DialogContent className="max-w-4xl">
                    <DialogHeader>
                      <DialogTitle>Available Models</DialogTitle>
                    </DialogHeader>
                    <div className="grid gap-4 py-4 max-h-[80vh] overflow-y-auto">
                      {Array.isArray(models) && models.map((model) => ( // Changed from mlModels to models
                        <div key={model.id} className="flex items-center justify-between p-4 border border-border rounded-md bg-card/70 hover:bg-card/90 transition-all card-hover">
                          <div>
                            <h3 className="font-medium">{model.name}</h3>
                            <p className="text-sm text-muted-foreground">{model.description}</p>
                            <div className="flex items-center mt-2">
                              <Badge className={cn(
                                "status-badge",
                                model.status === "active" ? "active" : 
                                model.status === "training" ? "training" : 
                                "inactive"
                              )}>
                                {model.status}
                              </Badge>
                              <span className="mx-2 text-muted-foreground text-xs">•</span>
                              <span className="text-xs text-muted-foreground">Type: {model.type}</span>
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            <Button 
                              variant="outline" 
                              size="sm" 
                              disabled={model.status === "training"}
                              onClick={() => handleRunModel(model)}
                            >
                              <PlayCircle className="mr-1 h-4 w-4" />
                              Run
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </DialogContent>
                </Dialog>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="flex items-center justify-center py-12">
                  <RefreshCw className="h-8 w-8 text-muted-foreground animate-spin mr-2" />
                  <p className="text-muted-foreground">Loading models...</p>
                </div>
              ) : sortedModels.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-12 text-center">
                  <AlertCircle className="h-12 w-12 text-muted-foreground mb-3" />
                  {/* TODO: Differentiate between no models at all vs. no models matching filters after API call */}
                  <h3 className="font-medium text-lg mb-1">No Models Found</h3>
                  <p className="text-muted-foreground">There are currently no models available or your filters cleared all results.</p>
                  <Button variant="outline" className="mt-4" onClick={() => {
                    setSearchTerm('');
                    setSelectedStatuses(['active', 'training', 'inactive']); 
                    setSortBy('');
                    setRefreshKey(prev => prev + 1); // Also trigger a refresh
                  }}>
                    Reset Filters & Refresh
                  </Button>
                </div>
              ) : (
                <div className="divide-y divide-border">
                  {sortedModels.map((model, index) => ( 
                    <div 
                      key={model.id} 
                      className="py-4 first:pt-0 last:pb-0 animate-fade-in-up"
                      style={{ animationDelay: `${index * 0.1}s` }}
                    >
                      <div className="flex flex-col md:flex-row md:items-center md:justify-between">
                        <div>
                          <div className="flex items-center">
                            <h3 className="font-medium">{model.name}</h3>
                            <Badge className={cn(
                              "ml-2",
                              "status-badge",
                              model.status === "active" ? "active" : 
                              model.status === "training" ? "training" : 
                              "inactive"
                            )}>
                              {model.status}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground mt-1">{model.description}</p>
                          <div className="flex items-center mt-2 text-xs text-muted-foreground">
                            <span className="mr-4">Type: {model.type}</span>
                            {/* Updated to handle null lastTrained and format date */}
                            <span>Last trained: {model.lastTrained ? new Date(model.lastTrained).toLocaleDateString() : 'N/A'}</span>
                          </div>
                        </div>
                        
                        <div className="mt-4 md:mt-0">
                          <div className="flex items-center">
                            <div className="text-right mr-4">
                              <div className="text-sm">Accuracy</div>
                              {/* Updated to handle null accuracy */}
                              <div className="font-medium">{model.accuracy ? `${(model.accuracy * 100).toFixed(2)}%` : 'N/A'}</div>
                            </div>
                            <div className="w-24 h-2 bg-muted rounded-full overflow-hidden">
                              <div 
                                className={cn(
                                  "h-full rounded-full",
                                  ((model.accuracy * 100) || 0) > 95 ? "bg-green-500" :
                                  ((model.accuracy * 100) || 0) > 90 ? "bg-blue-500" :
                                  ((model.accuracy * 100) || 0) > 85 ? "bg-amber-500" : "bg-red-500"
                                )} 
                                style={{ width: `${(model.accuracy * 100) || 0}%` }} // Handle null accuracy
                              ></div>
                            </div>
                          </div>
                        </div>
                        
                        <div className="flex flex-col space-y-2 mt-4 md:mt-0 md:flex-row md:space-y-0 md:space-x-2">
                          <Dialog>
                            <DialogTrigger asChild>
                              <Button variant="outline" size="sm" disabled={model.status !== "active"}>
                                <BarChart className="mr-1 h-4 w-4" />
                                View Metrics
                              </Button>
                            </DialogTrigger>
                            <DialogContent className="max-w-2xl h-[500px] top-[30%]">
                              <DialogHeader>
                                <DialogTitle>{model.name} Metrics</DialogTitle>
                              </DialogHeader>
                              {/* Pass the full model object to ModelMetrics */}
                              <ModelMetrics model={model} />
                            </DialogContent>
                          </Dialog>
                          
                          {runningModels[model.id]?.running ? (
                            <div className="flex items-center gap-2">
                              <div className="flex-1 min-w-[120px]">
                                <Progress 
                                  value={runningModels[model.id]?.progress || 0} 
                                  className="h-2"
                                />
                                <div className="text-xs text-muted-foreground mt-1">
                                  {runningModels[model.id]?.progress || 0}% Complete
                                </div>
                              </div>
                              <Button 
                                variant="destructive" 
                                size="sm"
                                onClick={() => handleStopModel(model)} // Ensure handleStopModel uses the new model structure
                              >
                                <StopCircle className="h-4 w-4" />
                              </Button>
                            </div>
                          ) : (
                            <Button 
                              variant="outline" 
                              size="sm" 
                              disabled={model.status === "training" || (runningModels[model.id]?.progress === 100)}
                              onClick={() => handleRunModel(model)} // Ensure handleRunModel uses the new model structure
                              className={cn(
                                runningModels[model.id]?.progress === 100 ? "bg-green-500/10 text-green-500" : ""
                              )}
                            >
                              {runningModels[model.id]?.progress === 100 ? (
                                <>
                                  <Check className="mr-1 h-4 w-4" />
                                  Complete
                                </>
                              ) : (
                                <>
                                  <PlayCircle className="mr-1 h-4 w-4" />
                                  Run
                                </>
                              )}
                            </Button>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
};

export default Models;
