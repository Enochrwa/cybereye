
import React, { useState } from 'react';
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { BarChart2, LineChart, PieChart, Activity, Download } from 'lucide-react';
import { Button } from "@/components/ui/button";

// Define ModelData interface matching the one in Models.tsx, including optional metrics
interface ModelData {
  id: string;
  name: string;
  status: 'active' | 'inactive' | 'training';
  accuracy: number | null;
  lastTrained: string | null;
  description: string;
  type: string;
  features?: string[];
  f1Score?: number | null;
  precision?: number | null;
  recall?: number | null;
  auc?: number | null;
  confusionMatrixData?: Array<{ label: string; values: number[] }> | null;
  featureImportanceData?: { name: string, importance: number }[];
}

const ModelMetrics = ({ model }: { model: ModelData }) => {
  const [metricView, setMetricView] = useState('performance');

  const renderMetricContent = () => {
    if (model.status === 'training') {
      return (
        <div className="flex flex-col items-center justify-center h-60 text-muted-foreground">
          <Activity className="w-12 h-12 mb-3" />
          <p>Metrics will be available after model training is complete.</p>
        </div>
      );
    }

    switch(metricView) {
      case 'performance':
        return <PerformanceMetrics model={model} />;
      case 'confusion':
        return <ConfusionMatrix model={model} />;
      case 'roc':
        return <ROCCurve model={model} />;
      case 'feature':
        return <FeatureImportance model={model} />;
      default:
        return <PerformanceMetrics model={model} />;
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center justify-between">
          <div className="flex items-center">
            <Activity className="mr-2" size={16} />
            {model.name} Metrics ({model.type})
          </div>
          <Button variant="outline" size="sm" disabled={model.status === 'training'}>
            <Download className="mr-2 h-4 w-4" />
            Export
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue={metricView} onValueChange={setMetricView}>
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="performance" disabled={model.status === 'training'}>Performance</TabsTrigger>
            <TabsTrigger value="confusion" disabled={model.status === 'training'}>Confusion Matrix</TabsTrigger>
            <TabsTrigger value="roc" disabled={model.status === 'training'}>ROC Curve</TabsTrigger>
            <TabsTrigger value="feature" disabled={model.status === 'training'}>Feature Importance</TabsTrigger>
          </TabsList>
          <TabsContent value={metricView} className="mt-4">
            {renderMetricContent()}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

const PerformanceMetrics = ({ model }: { model: ModelData }) => {
  return (
    <div className="space-y-6">
      {/* Accuracy over time (Static for now) */}
      <div>
        <h3 className="text-sm font-medium mb-2">Accuracy & Loss Over Time (Illustrative)</h3>
        <div className="border border-border rounded-md p-4 h-60">
          <div className="h-full relative">
            {/* X axis */}
            <div className="absolute bottom-0 left-0 right-0 h-[1px] bg-border"></div>
            {/* X axis labels */}
            <div className="absolute bottom-[-20px] left-0 right-0 flex justify-between text-xs text-muted-foreground">
              <span>0</span>
              <span>20</span>
              <span>40</span>
              <span>60</span>
              <span>80</span>
              <span>100</span>
            </div>
            {/* Y axis */}
            <div className="absolute top-0 bottom-0 left-0 w-[1px] bg-border"></div>
            {/* Y axis labels */}
            <div className="absolute top-0 bottom-0 left-[-25px] flex flex-col justify-between text-xs text-muted-foreground">
              <span>100%</span>
              <span>75%</span>
              <span>50%</span>
              <span>25%</span>
              <span>0%</span>
            </div>
            
            {/* Accuracy line (Static example) */}
            <svg className="absolute inset-0 h-full w-full overflow-visible" preserveAspectRatio="none">
              <polyline
                points="0,200 20,150 40,120 60,80 80,60 100,40 120,35 140,30 160,28 180,25 200,20" // Example data points
                fill="none"
                stroke="#3b82f6" // Blue
                strokeWidth="2"
                className="accuracy-line"
                style={{ vectorEffect: 'non-scaling-stroke' }}
              />
            </svg>
            
            {/* Loss line (Static example) */}
            <svg className="absolute inset-0 h-full w-full overflow-visible" preserveAspectRatio="none">
              <polyline
                points="0,50 20,70 40,90 60,100 80,105 100,110 120,115 140,116 160,118 180,118 200,119" // Example data points
                fill="none"
                stroke="#ef4444" // Red
                strokeWidth="2"
                className="loss-line"
                style={{ vectorEffect: 'non-scaling-stroke' }}
              />
            </svg>
            
            {/* Legend */}
            <div className="absolute top-2 right-2 flex items-center space-x-4 bg-background/80 backdrop-blur-sm p-1 rounded-md text-xs">
              <div className="flex items-center">
                <div className="w-2 h-2 bg-blue-500 mr-1"></div>
                <span className="">Accuracy</span>
              </div>
              <div className="flex items-center">
                <div className="w-2 h-2 bg-red-500 mr-1"></div>
                <span>Loss</span>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      {/* Key metrics */}
      <div className="grid grid-cols-2 gap-4">
        <div className="p-4 border border-border rounded-md">
          <div className="text-sm text-muted-foreground mb-1">Accuracy</div>
          <div className="text-md font-semibold">{model.accuracy !== null && model.accuracy !== undefined ? `${(model.accuracy * 100).toFixed(2) }%` : 'N/A'}</div>
        </div>
        
        <div className="p-4 border border-border rounded-md">
          <div className="text-sm text-muted-foreground mb-1">F1 Score</div>
          <div className="text-2xl font-semibold">{model.f1Score !== null && model.f1Score !== undefined ? model.f1Score.toFixed(3) : 'N/A'}</div>
        </div>
        
        <div className="p-4 border border-border rounded-md">
          <div className="text-sm text-muted-foreground mb-1">Precision</div>
          <div className="text-2xl font-semibold">{model.precision !== null && model.precision !== undefined ? model.precision.toFixed(3) : 'N/A'}</div>
        </div>
        
        <div className="p-4 border border-border rounded-md">
          <div className="text-sm text-muted-foreground mb-1">Recall</div>
          <div className="text-2xl font-semibold">{model.recall !== null && model.recall !== undefined ? model.recall.toFixed(3) : 'N/A'}</div>
        </div>
      </div>
    </div>
  );
};
const ConfusionMatrix = ({ model }) => {
  const matrix = model.confusion_matrix_data;

  if (!matrix || matrix.length === 0) {
    return (
      <div className="space-y-4">
        <h3 className="text-sm font-medium">Confusion Matrix</h3>
        <div className="border border-border rounded-md p-4 flex justify-center items-center h-60">
          <p className="text-muted-foreground text-center">
            Confusion matrix data is not available for this model.
          </p>
        </div>
      </div>
    );
  }

  const headers = matrix[0].values.map((_, i) => `Predicted Class ${i}`);
  const numCols = headers.length + 1;

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-medium">Confusion Matrix</h3>
      <div className="border border-border rounded-md p-4 flex justify-center overflow-x-auto">
        <div className="relative">
          <div className={`grid grid-cols-${numCols} gap-1 min-w-max`}>
            {/* Top-left empty cell */}
            <div className="h-10 sticky left-0 bg-card z-10"></div>
            
            {/* Header row */}
            {headers.map(header => (
              <div
                key={header}
                className="h-10 bg-muted flex items-center justify-center font-medium text-xs sm:text-sm px-2"
              >
                {header}
              </div>
            ))}

            {/* Data rows */}
            {matrix.map((row, i) => (
              <React.Fragment key={row.label}>
                {/* Row label */}
                <div className="h-16 bg-muted flex items-center justify-center font-medium text-xs sm:text-sm sticky left-0 bg-card z-10 px-2">
                  {row.label}
                </div>

                {/* Row values */}
                {row.values.map((value, j) => (
                  <div
                    key={j}
                    className={`h-16 flex items-center justify-center text-lg font-bold ${
                      i === j ? 'bg-green-500/20' : 'bg-red-500/10'
                    }`}
                  >
                    {value}
                  </div>
                ))}
              </React.Fragment>
            ))}
          </div>

          {/* Axis labels */}
          <div className="absolute -left-12 top-1/2 transform -translate-y-1/2 -rotate-90 text-sm text-muted-foreground">
            Actual
          </div>
          <div className="absolute top-0 left-1/2 transform -translate-x-1/2 -translate-y-6 text-sm text-muted-foreground">
            Predicted
          </div>
        </div>
      </div>
    </div>
  );
};

const ROCCurve = ({ model }: { model: ModelData }) => {
   if (model.auc === null || model.auc === undefined) { // Check specifically for auc for this component
     return (
      <div className="space-y-4">
        <h3 className="text-sm font-medium">ROC Curve</h3>
        <div className="border border-border rounded-md p-4 flex justify-center items-center h-60">
          <p className="text-muted-foreground text-center">
            ROC Curve data (AUC value) is not available for this model.
            </p>
        </div>
      </div>
    );
  }
  const aucValue = model.auc !== null && model.auc !== undefined ? model.auc.toFixed(3) : 'N/A';

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-medium">ROC Curve / AUC</h3>
      <div className="border border-border rounded-md p-4 h-60 relative">
        {/* Illustrative Axes and Dashed Line */}
        <div className="absolute top-0 bottom-0 left-10 w-[1px] bg-border"></div> {/* Y-axis line */}
        <div className="absolute bottom-10 left-0 right-0 h-[1px] bg-border"></div> {/* X-axis line */}
        <div className="absolute top-0 bottom-0 left-2 flex flex-col justify-between text-xs text-muted-foreground">
          <span>1.0</span><span>0.8</span><span>0.6</span><span>0.4</span><span>0.2</span><span>0.0</span> {/* Y-axis labels */}
        </div>
        <div className="absolute bottom-2 left-10 right-0 flex justify-between text-xs text-muted-foreground">
          <span>0.0</span><span>0.2</span><span>0.4</span><span>0.6</span><span>0.8</span><span>1.0</span> {/* X-axis labels */}
        </div>
        <div className="absolute -left-8 top-1/2 transform -translate-y-1/2 -rotate-90 text-xs text-muted-foreground">True Positive Rate</div>
        <div className="absolute bottom-4 left-1/2 transform -translate-x-1/2 text-xs text-muted-foreground">False Positive Rate</div>
        
        <svg className="absolute top-0 left-10 bottom-10 right-0" preserveAspectRatio="none"> {/* Reference dashed line */}
          <line x1="0%" y1="100%" x2="100%" y2="0%" stroke="#d4d4d8" strokeWidth="1" strokeDasharray="4,4"/>
        </svg>
        
        {/* Removed static SVG path for the curve itself */}
        
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 flex flex-col items-center justify-center">
          <div className="text-sm text-muted-foreground">AUC</div>
          <div className="text-3xl font-bold text-blue-500">{aucValue}</div>
        </div>
      </div>
      <div className="p-3 border border-border rounded-md bg-muted/10 text-sm">
        <div className="font-medium mb-1">Area Under Curve (AUC)</div>
        <p className="text-muted-foreground">
          The AUC value {aucValue !== 'N/A' ? `of ${aucValue}` : ''} indicates model discrimination. 
          A value closer to 1.0 is better. Random chance is 0.5.
          {aucValue === 'N/A' ? " Data currently unavailable for this model." : ""}
        </p>
      </div>
    </div>
  );
};

const FeatureImportance = ({ model }: { model: ModelData }) => {
  const featuresToDisplay = model.featureImportanceData 
    ? model.featureImportanceData 
    : model.features?.map(name => ({ name, importance: null as number | null }));

  if (!featuresToDisplay || featuresToDisplay.length === 0) {
    return (
      <div className="space-y-4">
        <h3 className="text-sm font-medium">Feature Importance</h3>
        <div className="border border-border rounded-md p-4 flex justify-center items-center h-40">
          <p className="text-muted-foreground">Feature importance data not available for this model.</p>
        </div>
      </div>
    );
  }
  
  const hasImportanceScores = featuresToDisplay.some(f => f.importance !== null && f.importance !== undefined);

  return (
    <div className="space-y-4">
      <h3 className="text-sm font-medium">Feature Importance</h3>
      <div className="border border-border rounded-md p-4">
        {featuresToDisplay.map((feature, i) => (
          <div key={i} className="mb-4 last:mb-0">
            <div className="flex justify-between mb-1">
              <span className="text-sm">{feature.name}</span>
              {feature.importance !== null && feature.importance !== undefined && (
                <span className="text-sm font-medium">{(feature.importance * 100).toFixed(1)}%</span>
              )}
            </div>
            <div className="w-full h-2 bg-muted rounded-full">
              {feature.importance !== null && feature.importance !== undefined ? (
                <div 
                  className="h-full bg-blue-500 rounded-full" 
                  style={{ width: `${Math.max(0, Math.min(100, feature.importance * 100))}%` }}
                ></div>
              ) : (
                <div 
                  className="h-full bg-gray-300 rounded-full"
                  style={{ width: `100%` }} 
                ><span className="sr-only">Importance not available</span></div>
              )}
            </div>
          </div>
        ))}
      </div>
      <div className="p-3 border border-blue-500/20 rounded-md bg-blue-500/5 text-sm">
        <div className="font-medium mb-1">Analysis</div>
        <p className="text-muted-foreground">
          Feature importance highlights the most influential factors for the model's predictions.
          {!hasImportanceScores && " Specific importance scores are not available; only feature names are listed."}
        </p>
      </div>
    </div>
  );
};

export default ModelMetrics;
