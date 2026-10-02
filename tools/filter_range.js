'use strict';
const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, '..', 'out2');
const lines = fs.readFileSync(path.join(dir, 'strings_all.txt'), 'utf8').split('\n');
const lo = 0x1803d0000n, hi = 0x180580000n;
const out = [];
for (const line of lines) {
  const tab = line.indexOf('\t');
  if (tab < 0) continue;
  const addr = BigInt(line.slice(0, tab));
  if (addr >= lo && addr <= hi) out.push(line);
}
fs.writeFileSync(path.join(dir, 'trainer_strings_range.txt'), out.join('\n'), 'utf8');
console.log('lines:', out.length);
