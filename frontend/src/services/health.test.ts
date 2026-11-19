// Run with: npm test (node --test, TypeScript types stripped by Node).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pickHealth, UNREACHABLE, type IngestionHealth } from './health.ts';

const idle: IngestionHealth = { status: 'HEALTHY', events_per_second: 0, avg_latency_ms: null, drop_rate_pct: null, active_devices: 2 };
const busy: IngestionHealth = { ...idle, events_per_second: 41.5 };
const mock: IngestionHealth = { status: 'HEALTHY', events_per_second: 12.5, avg_latency_ms: 4.2, drop_rate_pct: 0 };

test('an idle but reachable server is shown as reported, not as connecting', () => {
  assert.deepEqual(pickHealth(idle), idle);
});

test('a busy server is shown as reported', () => {
  assert.deepEqual(pickHealth(busy), busy);
});

test('a failed request says the API is unreachable', () => {
  assert.deepEqual(pickHealth(undefined), UNREACHABLE);
});

test('a malformed body is treated as unreachable', () => {
  assert.deepEqual(pickHealth({} as IngestionHealth), UNREACHABLE);
});

test('the dev-only mock only fills in when the server has nothing to show', () => {
  assert.deepEqual(pickHealth(busy, mock), busy);
  assert.deepEqual(pickHealth(idle, mock), mock);
  assert.deepEqual(pickHealth(undefined, mock), mock);
});
