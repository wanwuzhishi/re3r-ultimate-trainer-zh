// 一键构建：从你自备的原版修改器 DLL 生成简体中文汉化版。
// 用法:
//   node tools/build.js <原版DLL路径> [--upx <upx.exe路径>] [--out <输出目录>]
//
// 说明:
//   - 原版 DLL 可以是 UPX 加壳的原文件（Nexus/Patreon 下载的一般是加壳的），
//     也可以是已解壳的文件，脚本会自动识别。
//   - UPX 解壳需要 upx.exe（https://github.com/upx/upx/releases）。
//     可用 --upx 指定路径，或放到 PATH / 仓库根目录。
'use strict';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');

function parseArgs(argv) {
  const opts = { input: null, upx: null, out: path.join(ROOT, 'dist') };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--upx') opts.upx = argv[++i];
    else if (argv[i] === '--out') opts.out = argv[++i];
    else if (!opts.input) opts.input = argv[i];
  }
  return opts;
}

function parseSections(buf) {
  if (buf.readUInt16LE(0) !== 0x5A4D) throw new Error('不是有效的 PE 文件 (MZ 头缺失)');
  const e = buf.readUInt32LE(0x3c);
  const coff = e + 4;
  const n = buf.readUInt16LE(coff + 2);
  const so = coff + 20 + buf.readUInt16LE(coff + 16);
  const secs = [];
  for (let i = 0; i < n; i++) {
    const s = so + i * 40;
    secs.push({ name: buf.slice(s, s + 8).toString('ascii').replace(/\0+$/, '') });
  }
  return secs;
}

function findUpx(explicit) {
  const candidates = [];
  if (explicit) candidates.push(explicit);
  if (process.env.UPX_PATH) candidates.push(process.env.UPX_PATH);
  candidates.push(path.join(ROOT, 'upx.exe'));
  candidates.push(path.join(ROOT, 'upx-5.2.1-win64', 'upx.exe'));
  for (const c of candidates) {
    try { if (fs.existsSync(c)) return c; } catch (e) { /* ignore */ }
  }
  try {
    execFileSync('upx', ['--version'], { stdio: 'ignore' });
    return 'upx';
  } catch (e) { /* not on PATH */ }
  return null;
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (!opts.input) {
    console.error('用法: node tools/build.js <原版DLL路径> [--upx <upx.exe路径>] [--out <输出目录>]');
    process.exit(1);
  }
  if (!fs.existsSync(opts.input)) {
    console.error('找不到输入文件: ' + opts.input);
    process.exit(1);
  }
  fs.mkdirSync(opts.out, { recursive: true });
  const workDir = fs.mkdtempSync(path.join(require('os').tmpdir(), 're3rzh-'));

  // 1) 若为 UPX 加壳则解壳
  let unpacked = opts.input;
  const head = fs.readFileSync(opts.input).subarray(0, 0x400);
  const secNames = parseSections(head).map(s => s.name);
  if (secNames.some(n => n.startsWith('UPX'))) {
    const upx = findUpx(opts.upx);
    if (!upx) {
      console.error('\n检测到原版 DLL 为 UPX 加壳，需要 upx.exe 解壳。');
      console.error('请从 https://github.com/upx/upx/releases 下载 win64 版，');
      console.error('解压后用 --upx 参数指定 upx.exe 路径，或放到仓库根目录。\n');
      process.exit(1);
    }
    unpacked = path.join(workDir, 'unpacked.dll');
    console.log('[1/4] UPX 解壳中...');
    execFileSync(upx, ['-d', '-o', unpacked, opts.input], { stdio: 'inherit' });
  } else {
    console.log('[1/4] 输入文件未加壳，跳过解壳');
  }

  // 2) 打补丁
  console.log('[2/4] 应用汉化补丁...');
  const outDll = path.join(opts.out, 're3r_ultimate_trainer_zh.dll');
  const report = path.join(opts.out, 'patch_report.txt');
  execFileSync(process.execPath, [path.join(__dirname, 'patch.js'), unpacked, outDll, report], { stdio: 'inherit' });

  // 3) 校验
  console.log('[3/4] 校验补丁完整性...');
  execFileSync(process.execPath, [path.join(__dirname, 'verify.js'), unpacked, outDll], { stdio: 'inherit' });

  // 4) 生成对照表 + 中文模式开关文件
  console.log('[4/4] 生成翻译对照表...');
  execFileSync(process.execPath, [path.join(__dirname, 'make_table.js'), unpacked, report, path.join(opts.out, '翻译对照表.txt')], { stdio: 'inherit' });
  fs.writeFileSync(path.join(opts.out, 'reframework_pictographic.mode'), '');

  fs.rmSync(workDir, { recursive: true, force: true });
  console.log('\n构建完成! 输出目录: ' + opts.out);
  console.log('  re3r_ultimate_trainer_zh.dll ...... 汉化版修改器');
  console.log('  reframework_pictographic.mode .... 中文显示开关(空文件)');
  console.log('  翻译对照表.txt ................... 全部译文对照');
  console.log('\n安装: 把 re3r_ultimate_trainer_zh.dll 改名为 re3r_ultimate_trainer.dll，');
  console.log('  连同 reframework_pictographic.mode 一起放入游戏目录对应位置:');
  console.log('  <游戏根目录>/reframework/plugins/re3r_ultimate_trainer.dll');
  console.log('  <游戏根目录>/reframework_pictographic.mode   (注意: 必须在游戏根目录!)');
  console.log('详见 README.md。');
}

main();
