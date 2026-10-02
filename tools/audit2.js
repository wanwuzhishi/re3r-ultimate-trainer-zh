// Comprehensive audit v2: EVERY lea-referenced literal in the trainer regions,
// excluding only: already-translated, snake_case keys, RTTI, obvious library noise.
// Single capitalized words are REPORTED (not skipped) - that's how names were missed.
'use strict';
const fs = require('fs');
const path = require('path');
const ROOT = path.join(__dirname, '..');
const buf = fs.readFileSync(path.join(ROOT, 'out', 're3r_ultimate_trainer_unpacked.dll'));

function parsePE(buf) {
  const e = buf.readUInt32LE(0x3c), coff = e + 4, opt = coff + 20;
  const n = buf.readUInt16LE(coff + 2), sz = buf.readUInt16LE(coff + 16), so = opt + sz;
  const ib = buf.readBigUInt64LE(opt + 24);
  const secs = [];
  for (let i = 0; i < n; i++) {
    const s = so + i * 40;
    secs.push({ name: buf.slice(s, s + 8).toString('ascii').replace(/\0+$/, ''),
      vsize: buf.readUInt32LE(s + 8), vaddr: buf.readUInt32LE(s + 12),
      rawsize: buf.readUInt32LE(s + 16), rawptr: buf.readUInt32LE(s + 20) });
  }
  return { ib, secs };
}
const pe = parsePE(buf);
const isStrChar = c => (c >= 0x20 && c <= 0x7e) || c === 0x0a || c === 0x0d || c === 0x09;

const literals = new Map();
for (const sec of pe.secs) {
  if (!['.rdata', '.data'].includes(sec.name)) continue;
  let i = sec.rawptr;
  const end = sec.rawptr + sec.rawsize;
  while (i < end) {
    let j = i;
    while (j < end && isStrChar(buf[j])) j++;
    const len = j - i;
    if (j < end && buf[j] === 0 && len >= 2) {
      literals.set(pe.ib + BigInt(sec.vaddr + (i - sec.rawptr)), buf.slice(i, j).toString('ascii'));
      i = j + 1;
    } else i = (j > i ? j : i + 1);
  }
}
const text = pe.secs.find(s => s.name === '.text');
const leaRefs = new Map();
for (let i = text.rawptr; i < text.rawptr + text.rawsize - 7; i++) {
  const b0 = buf[i], b1 = buf[i + 1], b2 = buf[i + 2];
  if ((b0 === 0x48 || b0 === 0x4C) && b1 === 0x8D && (b2 & 0xC7) === 0x05) {
    const disp = buf.readInt32LE(i + 3);
    const target = pe.ib + BigInt(text.vaddr + (i + 7 - text.rawptr)) + BigInt(disp);
    leaRefs.set(target, (leaRefs.get(target) || 0) + 1);
    i += 6;
  }
}

const trans = new Map();
for (const f of ['trans_core.json', 'trans_stages.json', 'trans_items.json'])
  for (const [k] of Object.entries(JSON.parse(fs.readFileSync(path.join(ROOT, f), 'utf8'))))
    trans.set(BigInt(k), true);

// trainer code+data region ends before lua internals; be generous, filter by content
const LO = 0x1803d2f00n, HI = 0x18049c510n;
const out = [];
for (const [va, t] of literals) {
  if (va < LO || va >= HI) continue;
  if (trans.has(va)) continue;
  if (!(leaRefs.get(va) > 0)) continue;
  if (/^[a-z0-9_\-./\\:<>+~{}]+$/.test(t)) continue;            // keys/paths
  if (/^\.\?|^\\\\\?|^\?\?_/.test(t)) continue;                 // RTTI
  if (/^(sol:|sol2|lua|Lua|LUA|basic_string|__cdecl|std::|class |struct |enum |union |void |int |bool |char |const |unsigned|anonymous)/.test(t)) continue;
  if (/(ctti_get_type_name|lua_State|GLM|glm|CryptoPP|NameValuePairs|StreamTransformation|ImFontAtlas|ImFont_|ImGui|imgui|Json|json|exception|out of range|invalid|memory|allocator)/.test(t) && t.length > 20) continue;
  if (/^[0-9.]+$/.test(t)) continue;
  if (/^(pl[0-9]|IndirectLight)/.test(t)) continue;             // engine material/prop names
  out.push({ va, t, refs: leaRefs.get(va) });
}
out.sort((a, b) => (a.va < b.va ? -1 : 1));
fs.writeFileSync(path.join(ROOT, 'out2', 'audit2.txt'),
  out.map(r => `0x${r.va.toString(16)}\trefs=${r.refs}\t${JSON.stringify(r.t)}`).join('\n'), 'utf8');
console.log('audit2 rows:', out.length);
