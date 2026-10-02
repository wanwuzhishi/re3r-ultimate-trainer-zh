# RE3R Ultimate Trainer 简体中文汉化补丁生成器

生化危机3 重制版（RE3R）**Raz0r's Ultimate Trainer v2.0.3**（REFramework 插件版）的简体中文汉化工具。

本仓库**不包含任何原版或汉化后的二进制文件**，只包含翻译数据和一个补丁生成工具链：你自行下载原版修改器，一条命令在本地生成汉化版 DLL。

> **English**: This is a Simplified Chinese localization generator for Raz0r's Ultimate Trainer (RE3 Remake, REFramework plugin, v2.0.3). No binaries are distributed — run the build script against your own copy of the trainer to produce a localized DLL locally. [English quick start](#english-quick-start)

---

## ⚠️ 版权声明（请先阅读）

- 原版修改器 **Ultimate Trainer** 的版权归 **[Raz0r](https://www.patreon.com/_Raz0r)** 所有，请从 [Nexus Mods](https://www.nexusmods.com/residentevil32020/mods/9) 或其 Patreon 获取，并遵守原作者的使用条款。
- 本仓库只包含**自研的补丁工具链与翻译数据**，不含、也不分发原版或修改后的任何二进制文件。
- 本项目仅供学习交流，请勿用于商业用途。使用修改器联机产生的任何后果自负。

## 汉化覆盖范围

共约 **930 条**界面文本：主界面与全部分类（玩家/伙伴/物品/镜头/统计/佣兵）、全部功能开关与选项、热键界面、通知提示、约 200 个场景传送点名、物品/武器/改装件名称、敌人 ESP 名称、角色替换角色名、悬停帮助说明（含多行文本）。

**有意保留英文**：热键按键名（SHIFT/ENTER 等标准键名）、图形术语缩写（AF/AA/DOF/AO/SSR/TAA/HBAO+）、引擎敌人编号（em0000 等）与引擎材质名（Metallic、pl2000_Skin_Mat 等——它们同时是引擎查找键，翻译会破坏功能）。

## 使用方法

### 准备

1. 从 [Nexus Mods](https://www.nexusmods.com/residentevil32020/mods/9) 或 Raz0r 的 Patreon 下载 **Ultimate Trainer v2.0.3**（本工具按 v2.0.3 的字节布局编写，其他版本不保证可用）。
2. 安装 [REFramework](https://github.com/praydog/REFramework-nightly/releases)（RE3 用 `RE3.zip` 或 `RE3_TDB67.zip`）。
3. 安装 [Node.js](https://nodejs.org/)（任意近期版本）。
4. 若原版 DLL 为 UPX 加壳（Nexus 下载的一般是），还需 [UPX](https://github.com/upx/upx/releases) win64 版——把 `upx.exe` 放到仓库根目录、PATH 中，或用 `--upx` 参数指定。

### 一键生成

```bash
node tools/build.js "你的原版 re3r_ultimate_trainer.dll 路径"
```

脚本会自动完成：UPX 解壳（如需要）→ 应用补丁 → 完整性校验 → 生成对照表。输出在 `dist/` 目录：

| 文件 | 说明 |
|---|---|
| `re3r_ultimate_trainer_zh.dll` | 汉化版修改器（改名回 `re3r_ultimate_trainer.dll` 使用） |
| `reframework_pictographic.mode` | 中文显示开关（空文件，详见下文） |
| `patch_report.txt` / `翻译对照表.txt` | 补丁报告与全部译文对照 |

### 安装到游戏

1. 把 `re3r_ultimate_trainer_zh.dll` 改名为 `re3r_ultimate_trainer.dll`，放入 `<游戏根目录>/reframework/plugins/`（覆盖原版前请自行备份）。
2. 把 `reframework_pictographic.mode` 放到**游戏根目录**（`re3.exe` 旁边）。
3. 进游戏按 `Insert` 打开 REFramework 覆盖层，在 **Script Generated UI** 分类下即可看到全中文界面。

> **为什么需要那个空文件？** REFramework 内置了一个面向中文玩家的隐藏机制：只要游戏根目录存在 `reframework_pictographic.mode`（内容为空即可，只检测存在性），覆盖层字体就会从 Roboto 切换为内置的中文方正综艺体，并以完整中文字形范围（`GetGlyphRangesChineseFull`）渲染。没有它，汉化文本会显示为方块。

## 自定义翻译 / 贡献

所有译文都在 [`translations/`](translations/) 下的 4 个 JSON 文件里（键为 DLL 内的虚拟地址）：

| 文件 | 内容 |
|---|---|
| `trans_core.json` | 主界面、功能开关、提示、下拉选项 |
| `trans_stages.json` | 场景传送点名称 |
| `trans_items.json` | 物品/武器/改装件/货币名称 |
| `trans_sse.json` | 经 SSE 指令内联加载的短字符串（角色名、存档槽等，**译文不能超过原文长度**，超出会被构建脚本拒绝） |

改完后重新运行 `node tools/build.js ...` 即可。欢迎提交 Pull Request / Issue 反馈翻译问题。

## 技术原理（简述）

原版修改器是 UPX 加壳的 x64 原生 DLL，界面文本硬编码在 `.rdata` 中，存在三种引用方式，分别用不同策略处理：

1. **`lea` 指令引用**（约 860 条）：把译文（UTF-8）追加到 `.reloc` 节末尾形成新字符串区，逐条改写代码中 `lea r64, [rip+disp32]` 的 32 位位移，重定向到新地址。原始字节零改动，规避了 MSVC 字符串共享与长度限制问题。
2. **指针表引用**（1 条）：改写 `.data` 中的 8 字节指针（仅限带 `DIR64` 重定位项的真实指针）。
3. **SSE 内联构造**（72 条）：MSVC 对部分 SSO `std::string` 用 `movsd`/`mov`/`movzx` 数据块直接从 `.rdata` 搬运字节，长度立即数硬编码——这类字符串**原地覆写**，译文按原文长度空格补齐。

全部处理逻辑与校验规则见 [`tools/`](tools/)（补丁器 `patch.js`、校验器 `verify.js`，其余为逆向分析辅助脚本）。构建是确定性的：同一输入永远产出字节级相同的输出。

## 目录结构

```
├── translations/        翻译数据（JSON，按 DLL 虚拟地址索引）
├── tools/
│   ├── build.js         一键构建入口
│   ├── patch.js         补丁器
│   ├── verify.js        完整性校验器
│   ├── make_table.js    生成翻译对照表
│   └── *.js             逆向分析辅助脚本（字符串/引用扫描等）
├── 翻译对照表.txt        全部译文对照（预生成）
├── LICENSE              MIT（仅覆盖本仓库自有内容）
└── README.md
```

## 已知限制

- 字节布局按 **v2.0.3** 编写，原版更新后需要重新适配。
- 旧配置文件（`re3r_ultimate_trainer.settings`）与已绑定热键的内部键名未改动，可直接沿用；个别显示与键名合一的条目（如 Bloom）需重新绑定一次热键。
- 修改器中来自 DMC5 代码库的条目（血宫、魔人化等）在 RE3R 中通常不可见，已一并翻译。
- "物品添加"搜索框按中文关键词匹配（如输入"草药"）。

## English Quick Start

```bash
# Get the original trainer from Nexus Mods (v2.0.3), get upx.exe, then:
node tools/build.js "path/to/re3r_ultimate_trainer.dll"
# Output in dist/: localized DLL + reframework_pictographic.mode + translation table.
# Drop the DLL into <game>/reframework/plugins/ (rename to re3r_ultimate_trainer.dll)
# and the .mode file into the game root folder to enable CJK glyphs in REFramework.
```

## 鸣谢

- **[Raz0r](https://www.patreon.com/_Raz0r)** — Ultimate Trainer 原作者
- **[praydog](https://github.com/praydog/REFramework)** — REFramework
- [UPX](https://github.com/upx/upx) — 可执行文件解壳

## License

[MIT](LICENSE) — 仅覆盖本仓库自有的工具链代码与翻译数据。原版 Ultimate Trainer 的版权归 Raz0r 所有。
