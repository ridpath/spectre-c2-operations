import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('ErrorBoundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-950 flex items-center justify-center p-8">
          <div className="bg-red-500/10 border border-red-500/30 rounded-3xl p-12 max-w-2xl">
            <div className="flex items-center gap-4 mb-6">
              <AlertTriangle size={40} className="text-red-500" />
              <h1 className="text-2xl font-black text-red-400 uppercase tracking-tight">
                System Error
              </h1>
            </div>
            <p className="text-slate-400 mb-4">
              An unexpected error occurred in the application:
            </p>
            <pre className="bg-black/40 p-4 rounded-xl text-xs text-red-300 overflow-auto mb-6">
              {this.state.error?.message}
            </pre>
            <button
              onClick={() => window.location.reload()}
              className="px-6 py-3 bg-red-600 hover:bg-red-500 text-white rounded-xl font-bold uppercase text-sm transition-all"
            >
              Reload Application
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

export default ErrorBoundary;
