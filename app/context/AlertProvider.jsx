'use client';

import { createContext, useContext, useState, useEffect, useCallback } from 'react';
import AlertWebSocket from '../lib/websocket-client';

const AlertContext = createContext({});

export function AlertProvider({ children }) {
  const [alerts, setAlerts] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [subscribedAddresses, setSubscribedAddresses] = useState(new Set());
  const ws = AlertWebSocket;

  useEffect(() => {
    // Connect to WebSocket server
    ws.connect();

    // Set up event listeners
    ws.on('connected', () => {
      setIsConnected(true);
      console.log('WebSocket connected');
    });

    ws.on('disconnected', () => {
      setIsConnected(false);
      console.log('WebSocket disconnected');
    });

    ws.on('alert', (alert) => {
      setAlerts(prev => [alert, ...prev].slice(0, 50)); // Keep last 50 alerts
    });

    ws.on('error', (error) => {
      console.error('WebSocket error:', error);
    });

    // Cleanup on unmount
    return () => {
      ws.disconnect();
    };
  }, []);

  const subscribeToAddress = useCallback((address) => {
    const normalizedAddress = address.toLowerCase();
    ws.subscribe(normalizedAddress);
    setSubscribedAddresses(prev => new Set([...prev, normalizedAddress]));
  }, []);

  const unsubscribeFromAddress = useCallback((address) => {
    const normalizedAddress = address.toLowerCase();
    ws.unsubscribe(normalizedAddress);
    setSubscribedAddresses(prev => {
      const newSet = new Set(prev);
      newSet.delete(normalizedAddress);
      return newSet;
    });
  }, []);

  const clearAlerts = useCallback(() => {
    setAlerts([]);
  }, []);

  const value = {
    alerts,
    isConnected,
    subscribedAddresses,
    subscribeToAddress,
    unsubscribeFromAddress,
    clearAlerts,
  };

  return (
    <AlertContext.Provider value={value}>
      {children}
    </AlertContext.Provider>
  );
}

export function useAlerts() {
  const context = useContext(AlertContext);
  if (!context) {
    throw new Error('useAlerts must be used within an AlertProvider');
  }
  return context;
}
