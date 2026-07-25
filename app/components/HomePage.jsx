'use client';

import { useState } from 'react';
import { Activity, Shield } from 'lucide-react';
import { ChainSwitcher } from './ChainSwitcher';
import TokenAnalyzer from './TokenAnalyzer';
import RiskDashboard from './RiskDashboard';
import RealTimeAlerts from './RealTimeAlerts';

export default function HomePage() {
  const [analyzedTokens, setAnalyzedTokens] = useState([]);

  const handleAnalysisComplete = (result) => {
    setAnalyzedTokens((previous) => [result, ...previous].slice(0, 10));
  };

  return (
    <div className="min-h-screen text-white">
      <RealTimeAlerts />
      <header className="glass-card m-4 p-6">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-primary-500 p-3">
              <Shield className="h-8 w-8" />
            </div>
            <div>
              <h1 className="text-2xl font-bold">Rug Pull Detector</h1>
              <p className="text-sm text-gray-400">DeFi Token Scam Predictive Analytics</p>
            </div>
          </div>
          <div className="flex items-center gap-2 text-sm text-gray-400">
            <Activity className="h-4 w-4" />
            <span>API Status: Online</span>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-8">
        <div className="mb-8 max-w-3xl">
          <p className="text-sm uppercase tracking-[0.25em] text-primary-300">Next.js App Router</p>
          <h2 className="mt-2 text-4xl font-bold tracking-tight">Server-rendered token reports for better sharing and SEO</h2>
          <p className="mt-3 text-gray-300">
            Run an analysis from the form, then open the generated public report route for server-rendered previews and shareable links.
          </p>
        </div>

        {/* Chain Switcher */}
        <div className="mb-8">
          <ChainSwitcher />
        </div>

        <div className="grid gap-8 lg:grid-cols-2">
          <TokenAnalyzer onAnalysisComplete={handleAnalysisComplete} />
          <RiskDashboard analyzedTokens={analyzedTokens} />
        </div>
      </main>

      <footer className="glass-card m-4 p-4 text-center text-sm text-gray-400">
        <p>Built with Rust + Next.js App Router | Predictive Modeling for DeFi Security</p>
      </footer>
    </div>
  );
}
