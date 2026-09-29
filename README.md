# SmartPGP for NXP JCOP 4.5 / J3R452 (Hardware Curve25519)

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![JavaCard](https://img.shields.io/badge/JavaCard-3.0.5-orange.svg)]()
[![Hardware](https://img.shields.io/badge/NXP-J3R452%20%2F%20JCOP%204.5-red.svg)]()
[![Hardware Crypto](https://img.shields.io/badge/Hardware%20Crypto-Ed25519%20%2F%20X25519-green.svg)]()
[![Tests](https://img.shields.io/badge/Physical%20Card%20Verification-11%2F11%20PASSED-brightgreen.svg)]()

[English](#english) | [中文说明](#中文说明)

---

<a name="english"></a>
## English Documentation

### 📖 1. Project Background & Upstream Origins

This repository delivers a production-grade, cryptographically audited, and hardware-accelerated **OpenPGP Smart Card v3.4** implementation specifically engineered for **NXP JCOP 4.5 / J3R452** (P71D600 family) smart cards.

This project bridges and unifies two crucial open-source foundations:

1. **[github-af/SmartPGP](https://github.com/github-af/SmartPGP)** (and upstream [ANSSI-FR/SmartPGP](https://github.com/ANSSI-FR/SmartPGP)):
   - **Role**: Provides the robust high-level application architecture for the **OpenPGP Smart Card Specification v3.4**.
   - Handles all OpenPGP APDUs, data objects (DO), triple PIN verification (PW1 User, PW2 Reset, PW3 Admin), cryptographic key slots (Signature, Decryption, Authentication), SCP11b Secure Messaging, and lifecycle management.
   - *Upstream Limitation*: Official SmartPGP only supported RSA and standard Weierstrass curves (via standard Java Card `javacard.security` APIs), lacking Curve25519 on Java Card 3.0.5 platforms.

2. **[suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)**:
   - **Role**: Provides the low-level on-card hardware cryptographic wrapper package (AID: `FF00025519`) specifically written for the NXP J3R452 / JCOP 4.5 family.
   - Unlocks NXP's private, proprietary hardware coprocessor package (`D276000085304A434F5058 v1.24`) to execute Ed25519 and X25519 on-chip in silicon at constant time with Common Criteria EAL6+ certification.
   - Handles transparent, constant-time big-endian to little-endian byte-order translations (bridging NXP SecAPI with RFC 7748 and RFC 8032).
   - *Upstream Limitation*: It is purely a low-level cryptographic driver library without any OpenPGP application protocol logic.

#### The Problem Solved by This Project
The NXP J3R452 is an affordable, widely available smart card with a high-security CC EAL6+ coprocessor. However, because J3R452 runs **Java Card 3.0.5**, standard Java Card 3.1 APIs (`NamedParameterSpec.X25519`, `buildXECKey`) throw `NO_SUCH_ALGORITHM`. 

**This project seamlessly integrates `suut/Curve25519-JavaCard` into `github-af/SmartPGP`**, delivering native hardware-accelerated **Ed25519** (signing/authentication) and **X25519** (decryption) alongside full RSA and Weierstrass curve backward compatibility.

---

### 🌟 2. Key Capabilities & Performance

| Capability | Supported Specification | Performance on J3R452 |
| :--- | :--- | :--- |
| **Hardware Ed25519** | RFC 8032 (`1.3.6.1.4.1.11591.15.1`, Algorithm `0x16`) | **~220 ms** per signature |
| **Hardware X25519** | RFC 7748 (`1.3.6.1.4.1.3029.1.5.1`, Algorithm `0x12`) | **~50 ms** per key agreement |
| **Legacy RSA** | RSA 2048, 3072, 4096 CRT with PKCS#1 v1.5 | Hardware accelerated |
| **Weierstrass EC** | NIST P-256/384/521, Brainpool P-256/384/512 | Hardware accelerated |
| **OpenPGP Spec** | OpenPGP Smart Card Specification v3.4 | Compatible with GnuPG 2.2+ |
| **Use Cases** | Git commit signing, file decryption, SSH auth (`gpg-agent`) | 100% native support |

---

### 🛡️ 3. Cryptographic Security & Side-Channel Audit

1. **Zero Secret-Dependent Side Channels (Constant-Time Execution)**:
   - Scalar multiplication and EdDSA signing execute directly inside NXP's CC EAL6+ certified hardware engine.
   - All `if-else` branches in the code operate exclusively on **public metadata** (such as algorithm selection or input length validation). Zero branching depends on secret key bits, plaintexts, or intermediate state.
2. **Immediate Memory Zeroization**:
   - Private key buffers imported via APDU are scrubbed (`Util.arrayFillNonAtomic`) immediately upon being loaded into secure key containers.
   - During `PSO: DECIPHER` (X25519), ephemeral public key objects are wiped in a `finally` block (`clearKey()`), and scratch buffers are overwritten with zeros.
   - Upon applet deselect, `clearConnection()` purges transient buffers and session keys.
3. **Zero Dynamic Allocation (`new`) at Runtime**:
   - All crypto objects and transient buffers are pre-allocated once during applet installation (`install()`) in `CLEAR_ON_DESELECT` RAM, preventing EEPROM wear and memory exhaustion.
4. **Dual Format Compatibility**:
   - Accepts both standard 32-byte raw points and 33-byte points prefixed with `0x40` (RFC 4880bis / RFC 9580).

---

### 🧪 4. Physical Card Verification Results

Tested on a physical NXP J3R452 card via PC/SC (`tests/test_curve25519.py`):

```text
============================================================
 SmartPGP-J3R452-Curve25519 Hardware Verification Suite
============================================================
[1] SELECT OpenPGP Applet (AID: D27600012401)............... [SW: 9000] (76ms)
[2] VERIFY Admin PIN (12345678)............................. [SW: 9000]
[3] Set Algorithm Attributes for SIG (Ed25519).............. [SW: 9000]
[4] Set Algorithm Attributes for DEC (X25519)............... [SW: 9000]
[5] Set Algorithm Attributes for AUT (Ed25519).............. [SW: 9000]
[6] VERIFY User PIN Mode 81 (123456)........................ [SW: 9000]
[7] GENERATE KEY PAIR for SIG (Hardware Ed25519)............ [SW: 9000]
    Public Key (DO 7F49): 7F4922862088376D80DFE0E35879E35DCCB004EBC7AD8C12A49EF6A5C973E1F838F89EBEAB
[8] GENERATE KEY PAIR for DEC (Hardware X25519)............. [SW: 9000]
    Public Key (DO 7F49): 7F492286209CA28E4C3E14F31BF5675A91D86B1FAAE9E921C07354A37D9D7224D6116CC934
[9] PSO: COMPUTE DIGITAL SIGNATURE (Ed25519 64-byte)........ [SW: 9000]
[10] VERIFY User PIN Mode 82 for Decipher (123456).......... [SW: 9000]
[11] PSO: DECIPHER (Hardware X25519 ECDH 32-byte)........... [SW: 9000]
============================================================
  ALL 11 HARDWARE SECURITY TESTS PASSED 100% ON J3R452!
============================================================
```

And verified via system `gpg --card-status`:
```text
Application ID ...: D276000124010304AFAF000000000000
Version ..........: 3.4
Key attributes ...: ed25519 cv25519 ed25519
Signature counter : 1
```

---

### 🚀 5. Flashing to Card with GlobalPlatformPro (`gp`)

> [!IMPORTANT]
> You **MUST** load `Curve25519.cap` first before installing `SmartPGPApplet.cap`. The card installer will reject the applet if the driver package (`FF00025519`) is missing.

```cmd
:: 1. Load the Curve25519 hardware driver CAP (AID: FF00025519)
gp -r PCD --load lib\Curve25519.cap

:: 2. Install and instantiate the SmartPGP Applet
gp -r PCD --install dist\SmartPGPApplet.cap

:: 3. Verify on card
gp -r PCD -l
```

Or run `install.bat` / `./install.ps1` for automated deployment with JVM entropy pre-warming (preventing Windows SCardSvr 5s timeouts).

---

### ⚙️ 6. Building from Source

**Prerequisites**: JDK 11 and Apache Ant 1.10+.
```cmd
build.bat
```
Output binary: `dist/SmartPGPApplet.cap`

---

### 🔑 7. GnuPG Quick Start

- **Default User PIN**: `123456`
- **Default Admin PIN**: `12345678`

```bash
# 1. Inspect card status
gpg --card-status

# 2. Configure Curve25519 keys
gpg --card-edit
gpg/card> admin
gpg/card> key-attr
# Choose (2) ECC -> (1) Curve 25519 for Signature, Encryption, Authentication
gpg/card> generate
```

---

### 📄 8. License & Acknowledgments

This project is licensed under the **GNU General Public License v2 (GPL-2.0)** - see the [LICENSE](LICENSE) file for details.

- **[github-af/SmartPGP](https://github.com/github-af/SmartPGP)** & **[ANSSI-FR/SmartPGP](https://github.com/ANSSI-FR/SmartPGP)**: Original Java Card OpenPGP v3.4 implementation © ANSSI and SmartPGP contributors.
- **[suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)**: NXP J3R452 hardware Curve25519 library © suut.

---

<br><br>

---

<a name="中文说明"></a>
## 中文说明

### 📖 1. 项目背景与溯源致谢

本项目是专门针对 **NXP JCOP 4.5 / J3R452**（P71D600 系列）智能卡深度定制、通过严格密码学审计且具备纯硬件加速的 **OpenPGP 智能卡 v3.4** 实现方案。

本项目融合并深度重构了两个优秀的开源项目：

1. **[github-af/SmartPGP](https://github.com/github-af/SmartPGP)**（源自 [ANSSI-FR/SmartPGP](https://github.com/ANSSI-FR/SmartPGP)）：
   - **承担角色**：提供完整的 **OpenPGP Smart Card 规范 v3.4** 应用层协议栈。
   - 负责处理全部 OpenPGP APDU 指令、数据对象（DO）、三重 PIN 码校验（PW1 用户密码、PW2 重置密码、PW3 管理员密码）、三大密钥槽位（签名 SIG、解密 DEC、认证 AUT）、SCP11b 安全信道及生命周期管理。
   - *上游局限*：官方原版仅支持通过 Java Card 官方标准 API 实现的 RSA 与标准 Weierstrass 曲线（NIST / Brainpool），无法在 Java Card 3.0.5 平台使用硬件 Curve25519。

2. **[suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)**：
   - **承担角色**：提供专为 NXP J3R452 / JCOP 4.5 系列智能卡编写的底层硬件密码加速驱动包（AID: `FF00025519`）。
   - 接入并解锁了 NXP 原厂未公开的硬件协处理器私有接口（`D276000085304A434F5058 v1.24`），实现硅片级恒定时间（Constant-Time）的 Ed25519 签名与 X25519 密钥协商（具备 CC EAL6+ 硬件级物理防侧信道保护）。
   - 在底层实现透明的大小端序转换，使 NXP 协处理器与 RFC 7748、RFC 8032 标准无缝对接。
   - *上游局限*：仅为纯底层驱动库，不含任何 OpenPGP 应用层规范与指令交互逻辑。

#### 本项目解决的核心痛点
NXP J3R452 是目前市场上应用最广泛、性价比最高且通过 CC EAL6+ 认证的安全智能卡。虽然其硅片协处理器具备极强的 Curve25519 硬件加速能力，但因其运行 **Java Card 3.0.5** 规范，无法调用 Java Card 3.1 的标准 XECKey 接口（会直接抛出 `NO_SUCH_ALGORITHM`）。

**本项目成功桥接了两大开源基石**：在 `github-af/SmartPGP` 中深度集成 `suut/Curve25519-JavaCard` 驱动，既实现了原生硬件级极速 **Ed25519**（签名/SSH认证）与 **X25519**（解密），又完整保留了原版对 RSA（2048/3072/4096）与标准椭圆曲线的全部兼容性。

---

### 🌟 2. 核心特性与实测性能

| 功能模块 | 支持规格 | J3R452 实测耗时 |
| :--- | :--- | :--- |
| **硬件 Ed25519** | RFC 8032（OID: `1.3.6.1.4.1.11591.15.1`，算法代号 `0x16`） | 约 **220 ms** / 次签名 |
| **硬件 X25519** | RFC 7748（OID: `1.3.6.1.4.1.3029.1.5.1`，算法代号 `0x12`） | 约 **50 ms** / 次密钥协商 |
| **经典 RSA** | RSA 2048, 3072, 4096 CRT (带 PKCS#1 v1.5 填充) | 硬件加速 |
| **Weierstrass EC** | NIST P-256/384/521, Brainpool P-256/384/512 | 硬件加速 |
| **OpenPGP 规范** | OpenPGP Smart Card 规范 v3.4 | 原生兼容 GnuPG 2.2 / 2.3 / 2.4 / 2.5+ |
| **应用场景** | Git 提交签名、邮件与文件加解密、SSH 密钥认证 | 100% 即插即用 |

---

### 🛡️ 3. 密码学安全与侧信道审计要点

1. **恒定时间执行（防时序与功耗分析）**：
   - 标量乘法与 EdDSA 签名运算完全交由 NXP 芯片内部通过 CC EAL6+ 认证的硬件密码协处理器执行。
   - Java 代码中的所有 `if-else` 分支**严格属于公开元数据与指令路由**（例如算法选择或长度校验），绝对不存在任何依赖私钥内容、明文或中间状态的数据分支。
2. **敏感内存即时清零（Zeroization）**：
   - APDU 导入的私钥在存入持久安全容器后，其内存缓冲区立即通过 `Util.arrayFillNonAtomic` 清零。
   - `PSO: DECIPHER` 计算完成后，在 `finally` 块中立即调用 `clearKey()` 硬件擦除临时公钥，暂存计算区全部刷零。
   - 卡片在断开或反选（Deselect）时，自动触发 `clearConnection()` 销毁所有会话密钥与 RAM 临时数据。
3. **零运行期堆动态分配（无 `new`）**：
   - 彻底杜绝运行期 APDU 指令处理循环中的任何 `new` 操作。所有硬件句柄与临时解析对象均在 `install()` 安装期一次性预先分配在 `CLEAR_ON_DESELECT` 类型的 RAM 中，防止 EEPROM 磨损与碎片化。

---

### 🧪 4. 物理卡片实机 11 项全链路自动化测试报告

通过 PC/SC 在真实的 NXP J3R452 智能卡上运行 `tests/test_curve25519.py` 自动化测试套件：

```text
============================================================
 SmartPGP-J3R452-Curve25519 Hardware Verification Suite
============================================================
[1] 选择 SmartPGP Applet (AID: D27600012401)................. [SW: 9000] (76ms)
[2] 验证管理员 PIN (12345678)................................. [SW: 9000]
[3] 设置签名算法属性为 Ed25519............................... [SW: 9000]
[4] 设置解密算法属性为 X25519 (cv25519)...................... [SW: 9000]
[5] 设置认证算法属性为 Ed25519............................... [SW: 9000]
[6] 验证用户 PIN 模式 81 (123456)............................ [SW: 9000]
[7] 卡内原生生成 Ed25519 签名密钥对.......................... [SW: 9000]
    导出公钥 (DO 7F49): 7F4922862088376D80DFE0E35879E35DCCB004EBC7AD8C12A49EF6A5C973E1F838F89EBEAB
[8] 卡内原生生成 X25519 解密密钥对........................... [SW: 9000]
    导出公钥 (DO 7F49): 7F492286209CA28E4C3E14F31BF5675A91D86B1FAAE9E921C07354A37D9D7224D6116CC934
[9] 执行 PSO: 硬件原生 Ed25519 签名 (64字节)................. [SW: 9000]
[10] 验证用户 PIN 模式 82 解密权限 (123456)................... [SW: 9000]
[11] 执行 PSO: 硬件原生 X25519 ECDH 密钥协商 (32字节)........ [SW: 9000]
============================================================
  11 项硬件密码学安全测试全部 100% 通过！
============================================================
```

在系统终端执行官方 `gpg --card-status` 验证：
```text
Application ID ...: D276000124010304AFAF000000000000
Version ..........: 3.4
Key attributes ...: ed25519 cv25519 ed25519
Signature counter : 1
```

---

### 🚀 5. 使用 GlobalPlatformPro (`gp`) 刷卡指南

> [!IMPORTANT]
> 必须**先 `--load` 硬件驱动库，再 `--install` Applet**。若缺少底层依赖包 `FF00025519`，卡片会直接拒绝安装。

#### 命令行手动刷写：
```cmd
:: 第一步：载入底层 Curve25519 硬件驱动库 (AID: FF00025519)
gp -r PCD --load lib\Curve25519.cap

:: 第二步：安装并实例化 SmartPGP Applet
gp -r PCD --install dist\SmartPGPApplet.cap

:: 第三步：查看卡片状态确认就绪
gp -r PCD -l
```

#### 一键脚本安装（内置熵池预热，杜绝 Windows 5秒复位超时）：
```cmd
install.bat
```

---

### ⚙️ 6. 源码构建说明

**前置依赖**：JDK 11 与 Apache Ant 1.10+。
```cmd
build.bat
```
*(PowerShell 用户可执行 `./build.ps1`)*。构建产物输出于：`dist/SmartPGPApplet.cap`。

---

### 🔑 7. GnuPG 快速使用指南

- **默认用户 PIN（PW1）**：`123456`
- **默认管理员 PIN（PW3）**：`12345678`

```bash
# 1. 读取卡片信息
gpg --card-status

# 2. 进入交互式卡片编辑并修改密钥算法为 Curve25519
gpg --card-edit
gpg/card> admin
gpg/card> key-attr
# 分别对 Signature、Encryption、Authentication 槽位选择 (2) ECC -> (1) Curve 25519
gpg/card> generate
# 按提示输入 PIN 码即可在卡片内部生成全新的硬件密钥对
```

---

## 📄 开源许可证与致谢 (License & Credits)

本项目遵循 **GNU General Public License v2 (GPL-2.0)** 开源许可证协议 - 详见 [LICENSE](LICENSE) 文件。

### 致谢 (Acknowledgments)：
- **[github-af/SmartPGP](https://github.com/github-af/SmartPGP)** & **[ANSSI-FR/SmartPGP](https://github.com/ANSSI-FR/SmartPGP)**: 原始 Java Card OpenPGP v3.4 规范实现 © ANSSI 及 SmartPGP 开源贡献者。
- **[suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)**: NXP J3R452 底层硬件 Curve25519 协处理器驱动库 © suut。
