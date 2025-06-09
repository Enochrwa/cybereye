
import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AlertCircle, CheckCircle, Code, Database, Server, Zap } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";

const ModelTraining = () => {
  const [modelType, setModelType] = useState<string>("");
  const [dataSource, setDataSource] = useState<string>("");
  const [parameters, setParameters] = useState({
    epochs: 100,
    learningRate: 0.001,
    batchSize: 32,
    dropout: 0.2
  });
  const [isTraining, setIsTraining] = useState(false);
  const [progress, setProgress] = useState(0);
  const [activeTab, setActiveTab] = useState("configuration");
  const [trainingLogs, setTrainingLogs] = useState<string[]>([]);
  
  const { toast } = useToast();
  
  const handleParameterChange = (param: keyof typeof parameters, value: number) => {
    setParameters(prev => ({ ...prev, [param]: value }));
  };
  
  const startTraining = () => {
    // TODO: Replace with actual backend API call for model training.
    if (!modelType) {
      toast({
        title: "Model Type Required",
        description: "Please select a model type before starting training",
        variant: "destructive",
      });
      return;
    }
    
    if (!dataSource) {
      toast({
        title: "Data Source Required",
        description: "Please select a data source for training",
        variant: "destructive",
      });
      return;
    }
    
    setIsTraining(true);
    setProgress(0);
    setTrainingLogs([`[${new Date().toLocaleTimeString()}] Starting training simulation for ${modelType} model...`]);
    setActiveTab("progress");
    
    // Simulate training progress
    const interval = setInterval(() => {
      setProgress(prev => {
        // Ensure logs are updated via setTrainingLogs to avoid stale closures
        const currentLogCount = trainingLogs.length; 
        const newProgress = prev + Math.random() * 5;
        
        // Add logs at certain points
        const milestone = Math.floor(newProgress / 10) * 10;
        if (milestone > 0 && milestone <= 100 && Math.floor(prev / 10) * 10 < milestone) {
          const log = getLogMessage(milestone);
          setTrainingLogs(logs => [...logs, log]);
        }
        
        // Complete training
        if (newProgress >= 100) {
          clearInterval(interval);
          setProgress(100);
          setIsTraining(false);
          setTimeout(() => {
            toast({
              title: "Training Complete",
              description: `The ${modelType} model has been successfully trained`,
            });
            setTrainingLogs(logs => [...logs, `[${new Date().toLocaleTimeString()}] Training complete. Model saved.`]);
          }, 500);
          return 100;
        }
        
        return newProgress;
      });
    }, 500);
  };
  
  const getLogMessage = (progress: number) => {
    const timestamp = `[${new Date().toLocaleTimeString()}]`;
    switch(progress) {
      case 10:
        return `${timestamp} Initializing ${modelType} model architecture...`;
      case 20:
        return `${timestamp} Loading data from ${dataSource}...`;
      case 30:
        return `${timestamp} Data preprocessing complete. Starting training...`;
      case 40:
        return `${timestamp} Epoch 25/${parameters.epochs}: Loss: 0.4782, Accuracy: 68.5%`;
      case 50:
        return `${timestamp} Epoch 50/${parameters.epochs}: Loss: 0.3421, Accuracy: 78.2%`;
      case 60:
        return `${timestamp} Epoch 75/${parameters.epochs}: Loss: 0.2143, Accuracy: 85.7%`;
      case 70:
        return `${timestamp} Running validation... Validation accuracy: 83.1%`;
      case 80:
        return `${timestamp} Epoch 100/${parameters.epochs}: Loss: 0.1876, Accuracy: 91.3%`;
      case 90:
        return `${timestamp} Optimizing model parameters... Final tuning...`;
      default:
        return `${timestamp} Training in progress...`;
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center">
            <Zap className="mr-2 h-5 w-5" />
            Train New Model
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="configuration">Configuration</TabsTrigger>
            <TabsTrigger value="parameters">Parameters</TabsTrigger>
            <TabsTrigger value="progress">Progress</TabsTrigger>
          </TabsList>
          
          <TabsContent value="configuration" className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="model-type">Model Type</Label>
              <Select value={modelType} onValueChange={setModelType}>
                <SelectTrigger>
                  <SelectValue placeholder="Select model type" />
                </SelectTrigger>
                <SelectContent>
                  {/* TODO: Populate these items from backend-defined model types */}
                  <SelectItem value="anomaly-detection">Anomaly Detection (e.g., Neural Network)</SelectItem>
                  <SelectItem value="malware-classification">Malware Classification (e.g., RandomForest)</SelectItem>
                  <SelectItem value="user-behavior">User Behavior Analysis (e.g., LSTM)</SelectItem>
                  <SelectItem value="traffic-prediction">Traffic Prediction (e.g., ARIMA)</SelectItem>
                  <SelectItem value="intrusion-detection">Intrusion Detection (e.g., XGBoost)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="data-source">Data Source</Label>
              <Select value={dataSource} onValueChange={setDataSource}>
                <SelectTrigger>
                  <SelectValue placeholder="Select data source" />
                </SelectTrigger>
                <SelectContent>
                  {/* TODO: Populate these items from backend-defined data sources */}
                  <SelectItem value="network-logs">Network Logs (e.g., CICIDS2017)</SelectItem>
                  <SelectItem value="user-activity">User Activity Logs</SelectItem>
                  <SelectItem value="security-events">Security Event Logs (SIEM)</SelectItem>
                  <SelectItem value="system-metrics">System Performance Metrics</SelectItem>
                  <SelectItem value="traffic-flow">NetFlow/IPFIX Data</SelectItem>
                </SelectContent>
              </Select>
            </div>
            
            {modelType && dataSource && (
              <div className="p-4 border border-border rounded-md bg-muted/10 mt-4">
                <div className="flex items-center mb-2">
                  <CheckCircle className="h-5 w-5 text-green-500 mr-2" />
                  <h3 className="font-medium">Compatible Configuration</h3>
                </div>
                <p className="text-sm text-muted-foreground">
                  {getConfigDescription(modelType, dataSource)}
                </p>
              </div>
            )}
          </TabsContent>
          
          <TabsContent value="parameters" className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="epochs">
                Epochs: {parameters.epochs}
              </Label>
              <div className="flex items-center space-x-2">
                <Input
                  id="epochs"
                  type="range"
                  min={10}
                  max={500}
                  step={10}
                  value={parameters.epochs}
                  onChange={(e) => handleParameterChange('epochs', parseInt(e.target.value))}
                />
                <span className="w-12 text-center">{parameters.epochs}</span>
              </div>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="learningRate">
                Learning Rate: {parameters.learningRate}
              </Label>
              <div className="flex items-center space-x-2">
                <Input
                  id="learningRate"
                  type="range"
                  min={0.0001}
                  max={0.01}
                  step={0.0001}
                  value={parameters.learningRate}
                  onChange={(e) => handleParameterChange('learningRate', parseFloat(e.target.value))}
                />
                <span className="w-16 text-center">{parameters.learningRate}</span>
              </div>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="batchSize">
                Batch Size: {parameters.batchSize}
              </Label>
              <div className="flex items-center space-x-2">
                <Input
                  id="batchSize"
                  type="range"
                  min={8}
                  max={128}
                  step={8}
                  value={parameters.batchSize}
                  onChange={(e) => handleParameterChange('batchSize', parseInt(e.target.value))}
                />
                <span className="w-12 text-center">{parameters.batchSize}</span>
              </div>
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="dropout">
                Dropout: {parameters.dropout}
              </Label>
              <div className="flex items-center space-x-2">
                <Input
                  id="dropout"
                  type="range"
                  min={0}
                  max={0.5}
                  step={0.05}
                  value={parameters.dropout}
                  onChange={(e) => handleParameterChange('dropout', parseFloat(e.target.value))}
                />
                <span className="w-12 text-center">{parameters.dropout}</span>
              </div>
            </div>
            
            <div className="p-4 border border-border rounded-md bg-muted/10 mt-4">
              <div className="flex items-center mb-2">
                <AlertCircle className="h-5 w-5 text-amber-500 mr-2" />
                <h3 className="font-medium">Parameter Recommendations</h3>
              </div>
              <p className="text-sm text-muted-foreground">
                {getParameterRecommendation(modelType)}
              </p>
            </div>
          </TabsContent>
          
          <TabsContent value="progress">
            <div className="space-y-4">
              <div>
                <div className="flex justify-between mb-1">
                  <Label>Training Progress (Simulation)</Label>
                  <span className="text-sm">{Math.round(progress)}%</span>
                </div>
                <Progress value={progress} className="h-2" />
              </div>
              
              <div className="border border-border rounded-md p-2 bg-black/20 h-60 overflow-auto font-mono text-xs">
                {trainingLogs.length > 0 ? (
                  trainingLogs.map((log, i) => (
                    <div key={i} className="py-1 border-b border-border/30 last:border-0">
                      <span className="text-green-500">{log.split(']')[0]}]</span>
                      <span>{log.split(']')[1] || ''}</span>
                    </div>
                  ))
                ) : (
                  <div className="flex items-center justify-center h-full text-muted-foreground">
                    <Code className="mr-2 h-4 w-4" />
                    (Simulated logs will appear here once training starts)
                  </div>
                )}
              </div>
              
              <div className="flex justify-between">
                <div className="flex items-center text-xs text-muted-foreground">
                  <Server className="mr-1 h-4 w-4" />
                  <span>Simulated GPU Utilization: 86%</span>
                </div>
                <div className="flex items-center text-xs text-muted-foreground">
                  <Database className="mr-1 h-4 w-4" />
                  <span>Simulated Memory Usage: 4.2GB</span>
                </div>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
      <CardFooter className="justify-between">
        <Button variant="outline" onClick={() => {
          setModelType("");
          setDataSource("");
          setParameters({
            epochs: 100,
            learningRate: 0.001,
            batchSize: 32,
            dropout: 0.2
          });
          setProgress(0);
          setTrainingLogs([]);
          setActiveTab("configuration");
        }}>
          Reset
        </Button>
        <Button 
          onClick={startTraining} 
          disabled={isTraining || !modelType || !dataSource}
        >
          <Zap className="mr-2 h-4 w-4" />
          {isTraining ? "Training..." : "Start Training"}
        </Button>
      </CardFooter>
    </Card>
  );
};

// Helper functions
// TODO: These helper functions may need to be updated based on actual backend model types and their specific parameters/recommendations.
function getConfigDescription(modelType: string, dataSource: string): string {
  switch(modelType) {
    case 'anomaly-detection':
      return `This configuration will train an anomaly detection model using ${dataSource.replace('-', ' ')}. The model will learn normal patterns and identify deviations.`;
    case 'malware-classification':
      return `This configuration will train a malware classification model using ${dataSource.replace('-', ' ')} for identifying and categorizing potential threats.`;
    case 'user-behavior':
      return `This configuration will analyze ${dataSource.replace('-', ' ')} to model normal user behavior patterns and detect suspicious activities.`;
    case 'traffic-prediction':
      return `This configuration will use ${dataSource.replace('-', ' ')} to train a model predicting future network traffic patterns and potential bottlenecks.`;
    case 'intrusion-detection':
      return `This configuration will use ${dataSource.replace('-', ' ')} to train a model capable of detecting network intrusions and breaches.`;
    default:
      return "Select both model type and data source to see compatibility information.";
  }
}

function getParameterRecommendation(modelType: string): string {
  switch(modelType) {
    case 'anomaly-detection':
      return "For anomaly detection, consider using a higher learning rate (0.005) and more epochs (200+) to properly identify edge cases.";
    case 'malware-classification':
      return "For malware classification, a lower learning rate (0.0005) and larger batch size (64) typically yield better results.";
    case 'user-behavior':
      return "For user behavior analysis, we recommend a higher dropout rate (0.3-0.4) to prevent overfitting to specific user patterns.";
    case 'traffic-prediction':
      return "For traffic prediction models, consider fewer epochs (50-100) with a moderate learning rate (0.001) to capture general patterns.";
    case 'intrusion-detection':
      return "For intrusion detection, balance is key. Use moderate values for all parameters and consider increasing epochs if detection accuracy is low.";
    default:
      return "Select a model type to see parameter recommendations.";
  }
}

export default ModelTraining;
