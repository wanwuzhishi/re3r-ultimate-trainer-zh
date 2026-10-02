// 生成人类可读的 翻译对照表（英文原文 => 简体中文）。
// 数据来源: 补丁报告 (blob 条目) + 翻译表中的原地覆写条目 (原文取自原版 DLL)。
// 用法:
//   node tools/make_table.js <原版已解壳DLL> [报告文件] [输出TXT]
'use strict';
const fs = require('fs');
const path = require('path');
const ROOT = path.join(__dirname, '..');

const SRC_DLL = process.argv[2] || path.join(ROOT, 'dist', 'original_unpacked.dll');
const REPORT = process.argv[3] || path.join(ROOT, 'dist', 'patch_report.txt');
const OUT_TXT = process.argv[4] || path.join(ROOT, 'dist', '翻译对照表.txt');

const buf = fs.readFileSync(SRC_DLL);

function parseSections(buf) {
  const e = buf.readUInt32LE(0x3c), coff = e + 4, opt = coff + 20;
  const n = buf.readUInt16LE(coff + 2), szOpt = buf.readUInt16LE(coff + 16), secOff = opt + szOpt;
  const ib = buf.readBigUInt64LE(opt + 24);
  const secs = [];
  for (let i = 0; i < n; i++) {
    const s = secOff + i * 40;
    secs.push({
      name: buf.slice(s, s + 8).toString('ascii').replace(/\0+$/, ''),
      vsize: buf.readUInt32LE(s + 8), vaddr: buf.readUInt32LE(s + 12),
      rawsize: buf.readUInt32LE(s + 16), rawptr: buf.readUInt32LE(s + 20),
    });
  }
  return { ib, secs };
}
const { ib, secs } = parseSections(buf);
const va2off = va => {
  const rva = Number(va - ib);
  for (const s of secs) {
    if (rva >= s.vaddr && rva < s.vaddr + s.vsize) {
      const d = rva - s.vaddr;
      return d < s.rawsize ? s.rawptr + d : -1;
    }
  }
  return -1;
};

const rows = [];

// blob 条目 (来自补丁报告)
if (fs.existsSync(REPORT)) {
  const report = fs.readFileSync(REPORT, 'utf8').split('\n');
  for (const line of report) {
    const tab1 = line.indexOf('\t');
    if (tab1 < 0) continue;
    const tab2 = line.indexOf('\t->\t');
    if (tab2 < 0) continue;
    let en;
    try { en = JSON.parse(line.slice(tab1 + 1, tab2)); } catch (e) { continue; }
    const zh = line.slice(tab2 + 4);
    rows.push(en.replace(/[\r\n]+/g, ' / ') + '  =>  ' + zh.replace(/[\r\n]+/g, ' / '));
  }
}

// 原地覆写条目 (原文直接从原版 DLL 读取)
const sse = JSON.parse(fs.readFileSync(path.join(ROOT, 'translations', 'trans_sse.json'), 'utf8'));
for (const [k, zh] of Object.entries(sse)) {
  const off = va2off(BigInt(k));
  if (off < 0) continue;
  let j = off;
  while (j < buf.length && buf[j] !== 0 && j - off < 4000) j++;
  const en = buf.slice(off, j).toString('ascii');
  rows.push(en.replace(/[\r\n]+/g, ' / ') + '  =>  ' + zh.replace(/[\r\n]+/g, ' / ') + '   [原地覆写]');
}

rows.sort((a, b) => a.localeCompare(b, 'zh-Hans-CN'));
const out = 'RE3R 终极修改器 汉化对照表（英文原文 => 简体中文）\r\n'
  + '共 ' + rows.length + ' 条。基于 Raz0r Ultimate Trainer for RE3R v2.0.3。\r\n'
  + '='.repeat(70) + '\r\n\r\n' + rows.join('\r\n') + '\r\n';
fs.writeFileSync(OUT_TXT, out, 'utf8');
console.log('翻译对照表已生成:', OUT_TXT, '(' + rows.length + ' 条)');
