// Verify the patched DLL:
// 1) PE structure sane (sections, SizeOfImage, reloc directory size)
// 2) every patched lea resolves to a new-VA whose bytes decode to expected zh
// 3) report sanity: no translated VA held a snake_case / identifier-like EN text
'use strict';
const fs = require('fs');
const path = require('path');
const ROOT = path.join(__dirname, '..');

function parsePE(buf) {
  const e_lfanew = buf.readUInt32LE(0x3c);
  const coffOff = e_lfanew + 4;
  const numSections = buf.readUInt16LE(coffOff + 2);
  const sizeOfOptional = buf.readUInt16LE(coffOff + 16);
  const optOff = coffOff + 20;
  const imageBase = buf.readBigUInt64LE(optOff + 24);
  const sectionAlign = buf.readUInt32LE(optOff + 32);
  const sizeOfImage = buf.readUInt32LE(optOff + 56);
  const secOff = optOff + sizeOfOptional;
  const sections = [];
  for (let i = 0; i < numSections; i++) {
    const s = secOff + i * 40;
    sections.push({
      name: buf.slice(s, s + 8).toString('ascii').replace(/\0+$/, ''),
      vsize: buf.readUInt32LE(s + 8), vaddr: buf.readUInt32LE(s + 12),
      rawsize: buf.readUInt32LE(s + 16), rawptr: buf.readUInt32LE(s + 20),
      chars: buf.readUInt32LE(s + 36),
    });
  }
  return { imageBase, sectionAlign, sizeOfImage, sections, numSections, optOff };
}
const alignUp = (v, a) => Math.ceil(v / a) * a;

const SRC_DLL = process.argv[2] || path.join(ROOT, 'dist', 'original_unpacked.dll');
const PATCHED_DLL = process.argv[3] || path.join(ROOT, 'dist', 're3r_ultimate_trainer_zh.dll');
const buf = fs.readFileSync(PATCHED_DLL);
const src = fs.readFileSync(SRC_DLL);
const pe = parsePE(buf);
let ok = true;

const text = pe.sections.find(s => s.name === '.text');
// 1) structure
const reloc = pe.sections.find(s => s.name === '.reloc');
const srcReloc = parsePE(src).sections.find(s => s.name === '.reloc');
const srcText = parsePE(src).sections.find(s => s.name === '.text');
const expSizeOfImage = alignUp(reloc.vaddr + reloc.vsize, pe.sectionAlign);
console.log('[struct] sections:', pe.sections.map(s => `${s.name}(0x${s.vaddr.toString(16)},+0x${s.vsize.toString(16)})`).join(' '));
console.log('[struct] SizeOfImage 0x' + pe.sizeOfImage.toString(16), 'expected 0x' + expSizeOfImage.toString(16), pe.sizeOfImage === expSizeOfImage ? 'OK' : 'FAIL');
if (pe.sizeOfImage !== expSizeOfImage) ok = false;
console.log('[struct] .reloc chars 0x' + reloc.chars.toString(16), (reloc.chars & 0x02000000) === 0 ? '(discardable removed OK)' : 'FAIL');
const fileSizeOk = reloc.rawptr + reloc.rawsize === buf.length;
console.log('[struct] file size', buf.length, fileSizeOk ? 'OK' : 'FAIL');
if (!fileSizeOk) ok = false;
// other sections byte-identical to source? (.text/.data have expected diffs, checked below)
// .rdata now also has expected diffs: SSE in-place patches (trans_sse.json spans)
const sseSpans = [];
const secsForSse = pe.sections;
for (const [k, v] of Object.entries(JSON.parse(fs.readFileSync(path.join(ROOT, 'translations', 'trans_sse.json'), 'utf8')))) {
  const va = Number(BigInt(k));
  const rva = va - 0x180000000;
  let off = -1, secName = '';
  for (const s of secsForSse) {
    if (rva >= s.vaddr && rva < s.vaddr + s.vsize) {
      const d = rva - s.vaddr;
      if (d < s.rawsize) { off = s.rawptr + d; secName = s.name; }
      break;
    }
  }
  if (off < 0) throw new Error('sse va not mapped: ' + k);
  // span = original literal length (patcher space-pads to it)
  let litLen = 0;
  while (src[off + litLen] !== 0 && litLen < 4000) litLen++;
  sseSpans.push([off, off + litLen, secName]);
}
for (const s of pe.sections) {
  if (['.reloc', '.text', '.data', '.rdata'].includes(s.name)) continue;
  const a = buf.slice(s.rawptr, s.rawptr + s.rawsize);
  const b = src.slice(s.rawptr, s.rawptr + s.rawsize);
  if (!a.equals(b)) { console.log('[struct] section ' + s.name + ' differs from source: FAIL'); ok = false; }
}
// .text: diffs must be exactly the disp32 of translated leas
{
  const trans2 = new Map();
  for (const f of ['trans_core.json', 'trans_stages.json', 'trans_items.json'])
    for (const [k] of Object.entries(JSON.parse(fs.readFileSync(path.join(ROOT, 'translations', f), 'utf8'))))
      trans2.set(BigInt(k), true);
  const expected = new Set();
  for (let i = srcText.rawptr; i < srcText.rawptr + srcText.rawsize - 7; i++) {
    const b0 = src[i], b1 = src[i + 1], b2 = src[i + 2];
    if ((b0 === 0x48 || b0 === 0x4C) && b1 === 0x8D && (b2 & 0xC7) === 0x05) {
      const disp = src.readInt32LE(i + 3);
      const insnEndVA = pe.imageBase + BigInt(srcText.vaddr + (i + 7 - srcText.rawptr));
      if (trans2.has(insnEndVA + BigInt(disp))) {
        for (let d = 3; d < 7; d++) expected.add(i + d);
      }
      i += 6;
    }
  }
  const actual = new Set();
  const n = Math.min(buf.length, src.length);
  for (let i = text.rawptr; i < text.rawptr + text.rawsize && i < n; i++) {
    if (buf[i] !== src[i]) actual.add(i);
  }
  // every changed byte must be inside an expected disp32 (some disp bytes may coincide, so subset check)
  let subset = actual.size <= expected.size;
  if (subset) for (const o of actual) if (!expected.has(o)) { subset = false; break; }
  console.log(`[diff] .text changed bytes: ${actual.size} (of ${expected.size} disp32 bytes; some bytes coincidentally identical)`, subset ? 'OK' : 'FAIL');
  if (!subset) ok = false;
  // .data: diffs must be within one 8-aligned pointer slot plus its sse span
  const dataSec = pe.sections.find(s => s.name === '.data');
  const d = [];
  for (let i = dataSec.rawptr; i < dataSec.rawptr + dataSec.rawsize; i++) if (buf[i] !== src[i]) d.push(i);
  const dataSseSpans = sseSpans.filter(([a, b, sn]) => sn === '.data');
  const inDataSse = o => dataSseSpans.some(([a, b]) => o >= a && o < b);
  const dNonSse = d.filter(o => !inDataSse(o));
  let dOk = dNonSse.length > 0 && dNonSse.length <= 8;
  if (dOk) {
    const slotStart = dNonSse[0] - (dNonSse[0] % 8);
    dOk = dNonSse.every(o => o >= slotStart && o < slotStart + 8);
  }
  console.log(`[diff] .data changed bytes: ${d.length} (${dNonSse.length} pointer slot + ${d.length - dNonSse.length} sse)`, dOk ? 'OK' : 'FAIL');
  if (!dOk) ok = false;
}
// .rdata: diffs must be inside SSE in-place spans (plus each span fully overwritten with zh+space pad)
{
  const rdataSec = pe.sections.find(s => s.name === '.rdata');
  const inSpan = (o, sec) => sseSpans.some(([a, b, sn]) => o >= a && o < b && sn === sec);
  const d = [];
  for (let i = rdataSec.rawptr; i < rdataSec.rawptr + rdataSec.rawsize; i++) if (buf[i] !== src[i]) d.push(i);
  let rOk = d.length > 0;
  for (const o of d) if (!inSpan(o, '.rdata')) { rOk = false; console.log('[diff] .rdata byte outside sse spans: 0x' + o.toString(16)); break; }
  // every sse span's zh prefix must decode correctly
  for (const [k, v] of Object.entries(JSON.parse(fs.readFileSync(path.join(ROOT, 'translations', 'trans_sse.json'), 'utf8')))) {
    const rva2 = Number(BigInt(k)) - 0x180000000;
    let off = -1;
    for (const s of secsForSse) {
      if (rva2 >= s.vaddr && rva2 < s.vaddr + s.vsize) {
        const dd = rva2 - s.vaddr;
        if (dd < s.rawsize) off = s.rawptr + dd;
        break;
      }
    }
    const got = buf.slice(off, off + Buffer.from(v, 'utf8').length).toString('utf8');
    if (got !== v) { rOk = false; console.log('[diff] sse span mismatch at ' + k + ': ' + JSON.stringify(got)); }
  }
  console.log(`[diff] .rdata changed bytes: ${d.length} (inside ${sseSpans.length} sse spans)`, rOk ? 'OK' : 'FAIL');
  if (!rOk) ok = false;
}
// .reloc content up to old rawsize must be unchanged
if (!buf.slice(reloc.rawptr, reloc.rawptr + srcReloc.rawsize).equals(src.slice(srcReloc.rawptr, srcReloc.rawptr + srcReloc.rawsize))) {
  console.log('[struct] .reloc original content modified: FAIL'); ok = false;
}

// 2) lea verification
const trans = new Map();
for (const f of ['trans_core.json', 'trans_stages.json', 'trans_items.json'])
  for (const [k, v] of Object.entries(JSON.parse(fs.readFileSync(path.join(ROOT, 'translations', f), 'utf8'))))
    trans.set(BigInt(k), v);

const blobBaseDelta = srcReloc.rawsize; // first blob byte VA-delta from reloc.vaddr
let patchedLeas = 0, wrong = 0;
for (let i = text.rawptr; i < text.rawptr + text.rawsize - 7; i++) {
  const b0 = buf[i], b1 = buf[i + 1], b2 = buf[i + 2];
  if (!((b0 === 0x48 || b0 === 0x4C) && b1 === 0x8D && (b2 & 0xC7) === 0x05)) continue;
  const disp = buf.readInt32LE(i + 3);
  const insnEndVA = pe.imageBase + BigInt(text.vaddr + (i + 7 - text.rawptr));
  const target = insnEndVA + BigInt(disp);
  const targetRvaDelta = Number(target - pe.imageBase) - reloc.vaddr;
  if (targetRvaDelta >= blobBaseDelta && targetRvaDelta < blobBaseDelta + 200000) {
    // points into blob: decode and confirm it's one of our zh strings
    const fo = reloc.rawptr + targetRvaDelta;
    let k = fo;
    while (buf[k] !== 0) k++;
    const got = buf.slice(fo, k).toString('utf8');
    patchedLeas++;
    if (![...trans.values()].includes(got)) { wrong++; if (wrong < 5) console.log('[lea] blob target NOT in translations:', JSON.stringify(got)); }
  }
  i += 6;
}
console.log(`[lea] lea instructions pointing into blob: ${patchedLeas}, unexpected blob targets: ${wrong}`);
if (wrong) ok = false;

// every zh string must be targeted at least once (i.e., actually reachable)
const targeted = new Map();
{
  // count in source (old VAs) — reuse expected ref count from source leas to new VA mapping
  for (let i = srcText.rawptr; i < srcText.rawptr + srcText.rawsize - 7; i++) {
    const b0 = src[i], b1 = src[i + 1], b2 = src[i + 2];
    if (!((b0 === 0x48 || b0 === 0x4C) && b1 === 0x8D && (b2 & 0xC7) === 0x05)) continue;
    const disp = src.readInt32LE(i + 3);
    const insnEndVA = pe.imageBase + BigInt(srcText.vaddr + (i + 7 - srcText.rawptr));
    const target = insnEndVA + BigInt(disp);
    targeted.set(target, (targeted.get(target) || 0) + 1);
    i += 6;
  }
}
let unreachable = [];
for (const [va, zh] of trans) if (!targeted.has(va)) unreachable.push('0x' + va.toString(16) + ' ' + zh);
console.log(`[reach] translated strings with >=1 lea ref: ${trans.size - unreachable.length}/${trans.size}`);
if (unreachable.length) { console.log('  unreachable:', unreachable.join(', ')); }

// 3) report sanity: no identifier-like source text (报告缺失时跳过)
const reportPath = process.argv[4] || path.join(ROOT, 'dist', 'patch_report.txt');
if (fs.existsSync(reportPath)) {
  const report = fs.readFileSync(reportPath, 'utf8').split('\n');
  const suspicious = [];
  for (const line of report) {
    const m = line.match(/^0x([0-9a-f]+)\t"([^"]*)"\t->\t(.*)$/);
    if (!m) continue;
    const en = m[2];
    if (/^[a-z0-9_]+$/.test(en) || /^\.[?]|^\.\\?\?/.test(en)) suspicious.push(line);
    if (/^[A-Z][a-zA-Z0-9]*(Tip|Toast|Label|Btn|Header|Title)$/.test(en)) suspicious.push(line);
  }
  console.log(`[sanity] identifier-like source strings in report: ${suspicious.length}`);
  if (suspicious.length) { console.log(suspicious.slice(0, 20).join('\n')); ok = false; }
} else { console.log('[sanity] patch report not found, skipped'); }

console.log('\nRESULT:', ok ? 'ALL CHECKS PASSED' : 'CHECKS FAILED');
