# ext-permissions-helper

Comprehensive permissions management for Chrome extensions with request handling and user consent tracking.

## Features

- Permission request handling
- Preflight checks
- User consent tracking
- Permission history
- Rationale display
- TypeScript support

## Installation

```bash
npm install ext-permissions-helper
```

## Usage

```typescript
import { PermissionsManager } from 'ext-permissions-helper';

const perms = new PermissionsManager({
  required: [
    { type: 'api', value: 'storage' },
    { type: 'api', value: 'tabs' }
  ],
  optional: [
    { type: 'api', value: 'notifications' }
  ]
});

await perms.initialize();

// Check permissions
const hasAccess = await perms.hasAllRequired();

// Request permissions
const result = await perms.requestRequired();
```

## License

MIT
