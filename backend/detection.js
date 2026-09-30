const crypto = require('crypto');

const WINDOW_MS = 5 * 60 * 1000;
const FAILED_PATTERN = /failed|invalid|denied/i;
const AUTH_PATTERN = /ssh|login|authentication/i;
const WATCHED_SEVERITIES = new Set(['HIGH', 'CRITICAL']);

function evaluate(event, events) {
  if (!WATCHED_SEVERITIES.has(event.severity)) return null;
  if (!AUTH_PATTERN.test(`${event.category} ${event.message}`)) return null;

  const start = Date.now() - WINDOW_MS;
  const count = events.filter((item) =>
    item.source_ip === event.source_ip &&
    Date.parse(item.timestamp) >= start &&
    FAILED_PATTERN.test(item.message)
  ).length;

  if (count < 5) return null;

  return {
    id: `alert-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
    rule_key: 'auth-bruteforce-v1',
    created_at: new Date().toISOString(),
    source_ip: event.source_ip,
    severity: 'CRITICAL',
    status: 'NEW',
    title: 'Possible brute-force authentication attack',
    description: `${count} failed authentication events from ${event.source_ip} in five minutes.`,
    count
  };
}

module.exports = { evaluate };
