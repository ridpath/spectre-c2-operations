
import { useState, useCallback } from 'react';
import { TerminalLine } from '../types';

export const useTerminal = () => {
  const [lines, setLines] = useState<TerminalLine[]>([]);
  const [isExecuting, setIsExecuting] = useState(false);

  const addLine = useCallback((type: TerminalLine['type'], content: string) => {
    setLines(prev => [...prev, {
      id: Math.random().toString(36).substr(2, 9),
      type,
      content,
      timestamp: new Date()
    }]);
  }, []);

  const clearLines = useCallback(() => setLines([]), []);

  return {
    lines,
    addLine,
    clearLines,
    isExecuting,
    setIsExecuting
  };
};
