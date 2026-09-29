const fs = require('fs');
const path = require('path');
const dataDir = path.join(__dirname, '..', 'data');
const dataFile = path.join(dataDir, 'events.json');
fs.mkdirSync(dataDir, { recursive: true });
if (fs.existsSync(dataFile)) {
  const current = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
  if (current.length > 0) { console.log('Seed skipped: existing events were preserved.'); process.exit(0); }
}
const now = Date.now();
const events = [
  { id: `seed-${now}-1`, timestamp: new Date().toISOString(), severity: 'HIGH', category: 'authentication', source_ip: '192.0.2.10', message: 'Failed SSH login detected', hostname: 'gateway' },
  { id: `seed-${now}-2`, timestamp: new Date(now - 60000).toISOString(), severity: 'INFO', category: 'system', source_ip: '192.0.2.20', message: 'Service started', hostname: 'app-01' }
];
fs.writeFileSync(dataFile, JSON.stringify(events, null, 2));
console.log(`Seeded ${events.length} demo events.`);
