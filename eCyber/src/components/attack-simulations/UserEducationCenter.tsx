
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Book, AlertTriangle } from 'lucide-react';

const UserEducationCenter = () => {
  return (
    <Card className="overflow-hidden shadow-lg border-isimbi-purple/20">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Book className="h-5 w-5 text-isimbi-purple" />
          User Education Center
        </CardTitle>
        <CardDescription>Educational resources and tutorials on security best practices</CardDescription>
      </CardHeader>
      
      <CardContent className="p-6">
        <Tabs defaultValue="tutorials">
          <TabsList className="mb-6">
            <TabsTrigger value="tutorials">Tutorials</TabsTrigger>
            <TabsTrigger value="diagrams">Threat Diagrams</TabsTrigger>
            <TabsTrigger value="walkthrough">System Walkthrough</TabsTrigger>
          </TabsList>
          
          <TabsContent value="tutorials" className="pt-2">
            <div className="flex flex-col items-center justify-center py-8 text-center space-y-4">
              <AlertTriangle className="h-16 w-16 text-muted-foreground/50" />
              <div>
                <h3 className="text-lg font-semibold mb-2">Coming Soon</h3>
                <p className="text-sm text-muted-foreground">
                  Tutorial content is under development and will be available soon.
                </p>
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="diagrams" className="pt-2">
            <div className="flex flex-col items-center justify-center py-8 text-center space-y-4">
              <AlertTriangle className="h-16 w-16 text-muted-foreground/50" />
              <div>
                <h3 className="text-lg font-semibold mb-2">Coming Soon</h3>
                <p className="text-sm text-muted-foreground">
                  Threat diagrams are under development and will be available soon.
                </p>
              </div>
            </div>
          </TabsContent>
          
          <TabsContent value="walkthrough" className="pt-2">
            <div className="flex flex-col items-center justify-center py-8 text-center space-y-4">
              <AlertTriangle className="h-16 w-16 text-muted-foreground/50" />
              <div>
                <h3 className="text-lg font-semibold mb-2">Coming Soon</h3>
                <p className="text-sm text-muted-foreground">
                  System walkthrough content is under development and will be available soon.
                </p>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
};

export default UserEducationCenter;
