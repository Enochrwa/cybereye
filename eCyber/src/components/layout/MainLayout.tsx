
import React, { useState, useEffect } from 'react';
import Sidebar from "./Sidebar";
import { Outlet, useNavigate } from "react-router-dom"; // Added useNavigate
import Header from './Header';
import AIAssistant from "../common/AIAssistant";
import { useAuth } from "@/context/AuthContext"; // Added
import { useDispatch } from "react-redux"; // Added
import { setAuthModalState } from "@/app/slices/displaySlice"; // Added
import LoadingSpinner from '@/utils/LoadingSpinner'; // Added for better UX
import { ThemeToggle } from "@/components/ui/theme-toggle";
import { Shield, Bell } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Separator } from "@/components/ui/separator";

const MainLayout = () => {
  const [isMounted, setIsMounted] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  // const [notificationCount, setNotificationCount] = useState(3); // Not used in provided snippet
  
  const { isAuthenticated, isLoading: isAuthLoading } = useAuth(); // Get auth state
  const dispatch = useDispatch();
  const navigate = useNavigate();

  useEffect(() => {
    setIsMounted(true); // For AI Assistant, can be kept or removed if not essential for auth logic
  }, []);

  useEffect(() => {
    if (!isAuthLoading && !isAuthenticated) {
      // User is not authenticated and auth state is resolved
      dispatch(setAuthModalState(true)); // Open the login modal
      navigate('/', { replace: true }); // Redirect to home page, modal will overlay it
    }
  }, [isAuthenticated, isAuthLoading, dispatch, navigate]);

  const toggleSidebar = () => {
    setSidebarCollapsed(!sidebarCollapsed);
  };

  if (isAuthLoading) {
    // Show a loading spinner while authentication status is being determined
    return (
      <div className="flex items-center justify-center min-h-screen">
        <LoadingSpinner />
      </div>
    );
  }

  if (!isAuthenticated) {
    // User is not authenticated, and we've already dispatched to open modal and navigated to '/'.
    // Render null or a minimal spinner here as the modal should be handling the UI.
    // Navigating to '/' ensures that if the modal is closed without logging in, the user is on a safe public page.
    return null; // Or <LoadingSpinner /> or a message prompting login via modal
  }

  // If authenticated, render the main layout
  return (
    <div className="flex h-screen w-full bg-background">
      {/* Sidebar with responsive width */}
      <div 
        className={`hidden md:flex bg-gray-100 dark:bg-gray-900 border-r border-border transition-all duration-300 ${
          sidebarCollapsed ? "w-[60px]" : "w-[250px]"
        }`}
      >
        <Sidebar />
      </div>

      {/* Main content takes remaining width */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* Header*/}
        <header className="h-14 border-b border-border flex items-center justify-between px-4 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
          <div className="flex items-center">
            
            <h1 className="text-lg font-semibold hidden md:block">Security Operations Center</h1>
          </div>
          
          <div>
            <Header/>
          </div>
    
        </header>
        
        {/* Main content area */}
        <main className="flex-1 overflow-y-auto p-4">
          <Outlet /> {/* Render the actual protected page component */}
        </main>
        
        {/* AI Assistant only renders after initial mount to prevent hydration issues */}
        {isMounted && <AIAssistant />}
      </div>
    </div>
  );
};

export default MainLayout;
