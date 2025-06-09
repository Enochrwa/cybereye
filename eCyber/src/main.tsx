import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom'
import App from './App.tsx';
import './index.css';
import { AuthProvider } from './context/AuthContext'; // Import AuthProvider

import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "./components/theme/ThemeProvider";

import { Loader2 } from "lucide-react"; // For loading spinner

// Create a new query client with correct configuration
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});


const rootElement = document.getElementById('root');

if (!rootElement) {
  throw new Error('Root element not found');
}

import { Provider } from 'react-redux';

import { store } from './app/store.ts';

createRoot(rootElement).render(
  <React.StrictMode>
      <Provider store={store}>
        <QueryClientProvider client={queryClient}>
          <ThemeProvider defaultTheme="system" storageKey="theme">
            <TooltipProvider>
              <Toaster />
              <Sonner />
              <BrowserRouter>
                <AuthProvider>
                  <App/>
                </AuthProvider>
              </BrowserRouter>
            </TooltipProvider>
          </ThemeProvider>
        </QueryClientProvider>
      </Provider>
   
  </React.StrictMode>
);
