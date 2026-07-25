'use client';

import React, { useState } from 'react';
import { Bell, X, Wifi, WifiOff, AlertTriangle, Shield, TrendingDown, Users, AlertCircle } from 'lucide-react';
import { useAlerts } from '../context/AlertProvider';

function RealTimeAlerts() {
  const { alerts, isConnected, subscribedAddresses, subscribeToAddress, unsubscribeFromAddress, clearAlerts } = useAlerts();
  const [isOpen, setIsOpen] = useState(false);
  const [newAddress, setNewAddress] = useState('');

  const getAlertIcon = (alertType) => {
    if (alertType.type === 'LiquidityDrop') return <TrendingDown className="w-5 h-5" />;
    if (alertType.type === 'HolderConcentration') return <Users className="w-5 h-5" />;
    if (alertType.type === 'HoneypotDetected') return <AlertCircle className="w-5 h-5" />;
    if (alertType.type === 'MintableToken') return <Shield className="w-5 h-5" />;
    return <AlertTriangle className="w-5 h-5" />;
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'Low': return 'bg-blue-500/20 border-blue-500/50 text-blue-400';
      case 'Medium': return 'bg-yellow-500/20 border-yellow-500/50 text-yellow-400';
      case 'High': return 'bg-orange-500/20 border-orange-500/50 text-orange-400';
      case 'Critical': return 'bg-red-500/20 border-red-500/50 text-red-400';
      default: return 'bg-gray-500/20 border-gray-500/50 text-gray-400';
    }
  };

  const handleSubscribe = (e) => {
    e.preventDefault();
    if (newAddress.trim()) {
      subscribeToAddress(newAddress.trim());
      setNewAddress('');
    }
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString();
  };

  return (
    <div className="fixed top-4 right-4 z-50">
      {/* Alert Bell Button */}
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="relative p-3 bg-white/10 backdrop-blur-lg rounded-full border border-white/20 hover:bg-white/20 transition-colors"
      >
        <Bell className="w-6 h-6 text-white" />
        {alerts.length > 0 && (
          <span className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 rounded-full text-xs flex items-center justify-center text-white font-bold">
            {alerts.length}
          </span>
        )}
        {isConnected ? (
          <Wifi className="absolute -bottom-1 -right-1 w-3 h-3 text-green-400" />
        ) : (
          <WifiOff className="absolute -bottom-1 -right-1 w-3 h-3 text-red-400" />
        )}
      </button>

      {/* Alert Panel */}
      {isOpen && (
        <div className="absolute top-14 right-0 w-96 max-h-[80vh] overflow-hidden bg-gray-900/95 backdrop-blur-lg rounded-xl border border-white/20 shadow-2xl">
          {/* Header */}
          <div className="p-4 border-b border-white/10 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Bell className="w-5 h-5 text-primary-400" />
              <h3 className="font-semibold text-white">Real-Time Alerts</h3>
            </div>
            <button
              onClick={() => setIsOpen(false)}
              className="p-1 hover:bg-white/10 rounded transition-colors"
            >
              <X className="w-4 h-4 text-gray-400" />
            </button>
          </div>

          {/* Connection Status */}
          <div className="px-4 py-2 border-b border-white/10">
            <div className="flex items-center gap-2 text-sm">
              {isConnected ? (
                <>
                  <Wifi className="w-4 h-4 text-green-400" />
                  <span className="text-green-400">Connected</span>
                </>
              ) : (
                <>
                  <WifiOff className="w-4 h-4 text-red-400" />
                  <span className="text-red-400">Disconnected</span>
                </>
              )}
              <span className="text-gray-400">• {alerts.length} alerts</span>
            </div>
          </div>

          {/* Subscription Management */}
          <div className="p-4 border-b border-white/10">
            <form onSubmit={handleSubscribe} className="flex gap-2 mb-3">
              <input
                type="text"
                value={newAddress}
                onChange={(e) => setNewAddress(e.target.value)}
                placeholder="0x... address to monitor"
                className="flex-1 px-3 py-2 bg-white/5 border border-white/10 rounded-lg text-sm text-white placeholder-gray-400 focus:outline-none focus:border-primary-500"
              />
              <button
                type="submit"
                className="px-3 py-2 bg-primary-500 hover:bg-primary-600 text-white rounded-lg text-sm font-medium transition-colors"
              >
                Subscribe
              </button>
            </form>
            
            {subscribedAddresses.size > 0 && (
              <div className="space-y-1">
                <div className="text-xs text-gray-400 mb-2">Monitoring {subscribedAddresses.size} addresses</div>
                {Array.from(subscribedAddresses).slice(0, 3).map((address) => (
                  <div key={address} className="flex items-center justify-between bg-white/5 rounded px-2 py-1">
                    <span className="text-xs font-mono text-gray-300 truncate">{address}</span>
                    <button
                      onClick={() => unsubscribeFromAddress(address)}
                      className="text-xs text-red-400 hover:text-red-300"
                    >
                      Unsubscribe
                    </button>
                  </div>
                ))}
                {subscribedAddresses.size > 3 && (
                  <div className="text-xs text-gray-400">+{subscribedAddresses.size - 3} more</div>
                )}
              </div>
            )}
          </div>

          {/* Alerts List */}
          <div className="overflow-y-auto max-h-96">
            {alerts.length === 0 ? (
              <div className="p-8 text-center text-gray-400">
                <Bell className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p className="text-sm">No alerts yet</p>
                <p className="text-xs mt-1">Subscribe to addresses to receive alerts</p>
              </div>
            ) : (
              <div className="divide-y divide-white/10">
                {alerts.map((alert, index) => (
                  <div key={index} className="p-4 hover:bg-white/5 transition-colors">
                    <div className="flex items-start gap-3">
                      <div className={`p-2 rounded-lg ${getSeverityColor(alert.severity)}`}>
                        {getAlertIcon(alert.alert_type)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs font-mono text-primary-400 truncate">
                            {alert.address}
                          </span>
                          <span className="text-xs text-gray-400">
                            {formatTimestamp(alert.timestamp)}
                          </span>
                        </div>
                        <div className="text-sm text-white font-medium mb-1">
                          {alert.alert_type.type.replace(/([A-Z])/g, ' $1').trim()}
                        </div>
                        {alert.alert_type.type === 'LiquidityDrop' && (
                          <div className="text-xs text-gray-400">
                            {alert.alert_type.percentage.toFixed(1)}% drop (${alert.alert_type.previous.toLocaleString()} → ${alert.alert_type.current.toLocaleString()})
                          </div>
                        )}
                        {alert.alert_type.type === 'HolderConcentration' && (
                          <div className="text-xs text-gray-400">
                            {alert.alert_type.percentage.toFixed(1)}% held by top 10 wallets
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          {alerts.length > 0 && (
            <div className="p-3 border-t border-white/10">
              <button
                onClick={clearAlerts}
                className="w-full py-2 text-sm text-gray-400 hover:text-white hover:bg-white/10 rounded-lg transition-colors"
              >
                Clear All Alerts
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default RealTimeAlerts;
