
import React, { useEffect, useState } from 'react';
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Moon, Sun, Monitor } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";

type Theme = 'light' | 'dark' | 'system';

const ThemeSwitcher = () => {
  const [theme, setTheme] = useState<Theme>('system');
  const { toast } = useToast();
  
  // Load theme from localStorage on component mount
  useEffect(() => {
    const savedTheme = localStorage.getItem('theme') as Theme || 'system';
    setTheme(savedTheme);
    applyTheme(savedTheme);
  }, []);
  
  const applyTheme = (newTheme: Theme) => {
    // Remove existing classes
    document.documentElement.classList.remove('light', 'dark');
    
    // Apply the new theme
    if (newTheme === 'system') {
      const systemTheme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
      document.documentElement.classList.add(systemTheme);
    } else {
      document.documentElement.classList.add(newTheme);
    }
    
    // Save the theme preference
    localStorage.setItem('theme', newTheme);
  };
  
  const handleThemeChange = (newTheme: Theme) => {
    setTheme(newTheme);
    applyTheme(newTheme);
    
    toast({
      title: "Theme Updated",
      description: `Theme set to ${newTheme.charAt(0).toUpperCase() + newTheme.slice(1)}`,
    });
  };
  
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Theme Settings</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-3 gap-4">
          <ThemeOption 
            icon={Sun} 
            title="Light" 
            description=""
            isActive={theme === 'light'}
            onClick={() => handleThemeChange('light')}
          />
          
          <ThemeOption 
            icon={Moon} 
            title="Dark" 
            description=""
            isActive={theme === 'dark'}
            onClick={() => handleThemeChange('dark')}
          />
          
          <ThemeOption 
            icon={Monitor} 
            title="System" 
            description=""
            isActive={theme === 'system'}
            onClick={() => handleThemeChange('system')}
          />
        </div>
      </CardContent>
    </Card>
  );
};

interface ThemeOptionProps {
  icon: React.ElementType;
  title: string;
  description: string;
  isActive: boolean;
  onClick: () => void;
}

const ThemeOption: React.FC<ThemeOptionProps> = ({ icon: Icon, title, description, isActive, onClick }) => {
  return (
    <Button 
      variant={isActive ? "default" : "outline"} 
      className="h-auto flex flex-col items-center justify-center p-4 space-y-2"
      onClick={onClick}
    >
      <Icon className="h-6 w-6" />
      <div>
        <h3 className="font-medium">{title}</h3>
        <p className="text-xs text-muted-foreground">{description}</p>
      </div>
    </Button>
  );
};

export default ThemeSwitcher;
