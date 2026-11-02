import type { HealthResponse } from '@traceguard/shared';

export const healthyResponse = {
  status: 'ok', service: 'traceguard-api',
  timestamp: '2026-01-01T00:00:00.000Z', uptime: 42,
} satisfies HealthResponse;
