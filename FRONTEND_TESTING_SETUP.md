# Frontend Testing Setup Guide

**Status**: Not yet configured (0% test coverage)  
**Estimated Setup Time**: 30 minutes  
**Priority**: Medium (optional for production, recommended for maintenance)

---

## Current Status

The frontend currently has:
- ✅ **No test files** (clean slate)
- ❌ **No testing framework** installed
- ❌ **No test runner** configured
- ❌ **No test script** in package.json

---

## Recommended Setup

### 1. Install Testing Dependencies

```bash
npm install -D vitest @testing-library/react @testing-library/jest-dom @testing-library/user-event jsdom
```

**Packages**:
- `vitest` - Fast unit test framework (Vite-native)
- `@testing-library/react` - React component testing utilities
- `@testing-library/jest-dom` - DOM matchers
- `@testing-library/user-event` - User interaction simulation
- `jsdom` - DOM environment for tests

---

### 2. Create Vitest Configuration

Create `vitest.config.ts`:

```typescript
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html'],
      exclude: ['node_modules/', 'src/test/']
    }
  }
});
```

---

### 3. Create Test Setup File

Create `src/test/setup.ts`:

```typescript
import { expect, afterEach } from 'vitest';
import { cleanup } from '@testing-library/react';
import * as matchers from '@testing-library/jest-dom/matchers';

expect.extend(matchers);

afterEach(() => {
  cleanup();
});
```

---

### 4. Add Test Scripts to package.json

```json
{
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview",
    "test": "vitest",
    "test:ui": "vitest --ui",
    "test:coverage": "vitest --coverage"
  }
}
```

---

## Priority Components to Test

### High Priority (5 components)

1. **PayloadFactory** - Backend integration, form validation
2. **Terminal** - Command execution, output streaming
3. **EvidenceVault** - CRUD operations, authentication
4. **MissionPlanner** - Mission lifecycle management
5. **SatelliteOrchestrator** - WebSocket connections, 3D visualization

### Medium Priority (5 components)

6. **ModuleBrowser** - Module execution
7. **TorEgressMonitor** - Status monitoring
8. **OpSecMonitor** - Log display
9. **VulnerabilityScanner** - Nmap integration
10. **APTOrchestrator** - Chain execution

---

## Example Test: PayloadFactory

Create `components/PayloadFactory.test.tsx`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import PayloadFactory from './PayloadFactory';
import { payloadService } from '../services/payloadService';

vi.mock('../services/payloadService');
vi.mock('../services/geminiService');

describe('PayloadFactory', () => {
  const mockOnInsertCode = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(payloadService.getTemplates).mockResolvedValue({
      templates: [
        {
          id: 'powershell_reverse_tcp',
          name: 'PowerShell Reverse TCP',
          description: 'Staged PowerShell reverse TCP connection',
          format: 'powershell',
          evasion_level: 'moderate'
        }
      ],
      formats: ['powershell', 'exe', 'dll'],
      total: 1
    });
  });

  it('renders payload factory interface', () => {
    render(<PayloadFactory onInsertCode={mockOnInsertCode} />);
    expect(screen.getByText(/payload/i)).toBeInTheDocument();
  });

  it('loads templates on mount', async () => {
    render(<PayloadFactory onInsertCode={mockOnInsertCode} />);
    
    await waitFor(() => {
      expect(payloadService.getTemplates).toHaveBeenCalled();
    });
  });

  it('validates LHOST input', async () => {
    render(<PayloadFactory onInsertCode={mockOnInsertCode} />);
    const user = userEvent.setup();
    
    const lhostInput = screen.getByLabelText(/lhost|listener/i);
    await user.clear(lhostInput);
    await user.type(lhostInput, 'invalid-ip');
    
    // Add validation check assertion
  });

  it('generates payload with correct parameters', async () => {
    vi.mocked(payloadService.generatePayload).mockResolvedValue({
      success: true,
      payload: 'base64encodedpayload',
      size: 536
    });

    render(<PayloadFactory onInsertCode={mockOnInsertCode} />);
    const user = userEvent.setup();
    
    // Simulate form interaction and submission
    // Verify payloadService.generatePayload called with correct params
  });
});
```

---

## Example Test: SatelliteOrchestrator WebSocket

Create `components/SatelliteOrchestrator.test.tsx`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import SatelliteOrchestrator from './SatelliteOrchestrator';

describe('SatelliteOrchestrator', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('establishes WebSocket connection on mount', async () => {
    const mockSocket = {
      onopen: vi.fn(),
      onmessage: vi.fn(),
      onerror: vi.fn(),
      onclose: vi.fn(),
      send: vi.fn(),
      close: vi.fn()
    };

    global.WebSocket = vi.fn(() => mockSocket) as any;

    render(<SatelliteOrchestrator />);

    await waitFor(() => {
      expect(global.WebSocket).toHaveBeenCalledWith(
        expect.stringContaining('ws://localhost:8000/ws/orbital/')
      );
    });
  });

  it('handles incoming telemetry data', async () => {
    // Mock WebSocket and simulate telemetry messages
    // Verify component updates with new data
  });

  it('cleans up WebSocket on unmount', () => {
    const mockClose = vi.fn();
    const mockSocket = {
      close: mockClose,
      addEventListener: vi.fn()
    };

    global.WebSocket = vi.fn(() => mockSocket) as any;

    const { unmount } = render(<SatelliteOrchestrator />);
    unmount();

    expect(mockClose).toHaveBeenCalled();
  });
});
```

---

## Running Tests

```bash
# Run all tests (watch mode)
npm test

# Run tests once
npm test -- --run

# Generate coverage report
npm run test:coverage

# Open UI interface
npm run test:ui
```

---

## Expected Coverage Goals

- **Critical Components**: 80%+ coverage
- **Utility Functions**: 90%+ coverage
- **Service Layer**: 70%+ coverage
- **Overall Target**: 60%+ coverage

---

## Benefits of Adding Tests

1. **Regression Prevention** - Catch bugs before deployment
2. **Refactoring Safety** - Confidence when changing code
3. **Documentation** - Tests serve as usage examples
4. **CI/CD Integration** - Automated quality checks
5. **Developer Experience** - Faster feedback loop

---

## Notes

- **Backend has 100% test coverage** (41/41 tests passing)
- **Frontend has 0% test coverage** (not yet setup)
- Tests are **optional for production** but **recommended for maintenance**
- Estimated time to reach 60% coverage: **2-3 days**
