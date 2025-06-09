
import React from 'react';
import { AlertTriangle } from 'lucide-react';

const ContactSupport = () => {
  return (
    <div className="flex flex-col items-center justify-center py-8 text-center space-y-4">
      <AlertTriangle className="h-16 w-16 text-muted-foreground/50" />
      <div>
        <h3 className="text-lg font-semibold mb-2">Coming Soon</h3>
        <p className="text-sm text-muted-foreground">
          Contact and support features are under development and will be available soon.
        </p>
      </div>
    </div>
  );
};

export default ContactSupport;
