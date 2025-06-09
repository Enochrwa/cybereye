
import React from 'react';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { User, AlertTriangle } from 'lucide-react';

const BehavioralDeviationSimulation = () => {
  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader className="bg-gradient-to-r from-isimbi-navy to-isimbi-dark-charcoal">
        <div className="flex justify-between items-center">
          <div>
            <CardTitle className="flex items-center gap-2">
              <User className="h-5 w-5 text-isimbi-purple" />
              Behavioral Deviation
            </CardTitle>
            <CardDescription>Detect unusual user behavior patterns and anomalies</CardDescription>
          </div>
          <Badge variant="outline" className="ml-2">Ready</Badge>
        </div>
      </CardHeader>
      
      <CardContent className="p-6">
        <div className="flex flex-col items-center justify-center py-8 text-center space-y-4">
          <AlertTriangle className="h-16 w-16 text-muted-foreground/50" />
          <div>
            <h3 className="text-lg font-semibold mb-2">Coming Soon</h3>
            <p className="text-sm text-muted-foreground">
              This simulation module is currently under development and will be available soon.
            </p>
          </div>
        </div>
      </CardContent>
      
      <CardFooter className="bg-card/50 border-t border-border/50 flex justify-between">
        <div className="text-xs text-muted-foreground">
          Check back soon for updates
        </div>
        <Button disabled>Simulate Anomaly</Button>
      </CardFooter>
    </Card>
  );
};

export default BehavioralDeviationSimulation;
