# SmartPGP for NXP JCOP 4.5 / J3R452 (Hardware Curve25519)

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![JavaCard](https://img.shields.io/badge/JavaCard-3.0.5-orange.svg)]()
[![Hardware](https://img.shields.io/badge/NXP-J3R452%20%2F%20JCOP%204.5-red.svg)]()
[![Hardware Crypto](https://img.shields.io/badge/Hardware%20Crypto-Ed25519%20%2F%20X25519-green.svg)]()
[![Tests](https://img.shields.io/badge/Physical%20Card%20Verification-12%2F12%20PASSED-brightgreen.svg)]()

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

### 🛡️ 3. Cryptographic Security & Hardening Highlights

1. **Zero Secret-Dependent Side Channels (Constant-Time Execution)**:
   - Scalar multiplication and EdDSA signing execute directly inside NXP's CC EAL6+ certified hardware engine.
   - All `if-else` branches in the code operate exclusively on **public metadata** (such as algorithm selection or input length validation). Zero branching depends on secret key bits, plaintexts, or intermediate state.
   - Constant-time CMAC implementation with branchless subkey reduction and final-block handling.
2. **RFC 7748 §6 Zero Shared Secret & Small-Subgroup Detection**:
   - Strictly enforces constant-time zero shared secret detection on X25519 ECDH calculations.
   - If the shared secret is all zeros or maps to a small-subgroup root, transient buffers are immediately scrubbed and the operation is rejected, preventing small-subgroup attacks.
3. **Atomic Key Lifecycle & Tear Protection (Sentinel Pattern)**:
   - Curve25519 key slots use persistent valid status flags and bitwise inverse validation.
   - Key generation and import flows are guarded by an EEPROM sentinel flag pattern, ensuring that unexpected power loss or card tearing during generation cannot leave half-written keys in a usable state.
4. **RFC 7748 / RFC 8032 Scalar Clamping vs. Seed Preservation**:
   - Imported X25519 private keys undergo strict RFC 7748 §5 scalar clamping at the application layer.
   - Ed25519 private keys are preserved as raw 32-byte seeds per RFC 8032, allowing the underlying hardware engine to perform SHA-512 expansion and clamping internally, avoiding corrupted derivation chains.
5. **Runtime Signature Validation & Pre-Output Self-Verification**:
   - Enforces runtime assertions on Ed25519 signatures returned from the hardware coprocessor to guarantee exact 64-byte outputs (RFC 8032 §5.1.6).
   - Signatures (RSA, Ed25519, ECDSA) undergo on-chip verification prior to returning the APDU, mitigating physical and fault-injection risks that could leak private key fragments from erroneous signatures.
   - ECDSA signatures return fixed-width raw `r || s` (64 bytes for P-256, 96 bytes for P-384, 132 bytes for P-521).
6. **Immediate Sensitive Memory Zeroization**:
   - Transient RAM buffers are proactively cleared across PIN/PUK verification (`INS_VERIFY`, `INS_CHANGE_REFERENCE_DATA`, `INS_RESET_RETRY_COUNTER`), `PUT DATA` operations, and key deletion (`clearKey()`).
   - Upon applet deselect or connection reset, all transient session buffers and session keys are destroyed.
7. **Lazy-Loaded Engines & Zero-Duplicate Cipher Architecture**:
   - Shares a single AES engine across core applet routines, Secure Messaging (SCP11b), and CMAC verification.
   - Heavy cryptographic engines (RSA PKCS#1 ciphers, Weierstrass EC Diffie-Hellman, SHA-variant ECDSA signers, and Curve25519 hardware engines) are lazy-loaded on-demand via cached singletons. Static crypto engine instances at installation drop from 15 to 2, conserving critical JCOP System RAM (Tag 03) and eliminating COR RAM allocation conflicts.
8. **Dual Public Key Format Compatibility**:
   - Accepts both standard 32-byte raw points and 33-byte points prefixed with `0x40` (RFC 4880bis / RFC 9580).

---

### 🧪 4. Physical Card Verification Results

Tested on a physical NXP J3R452 card via PC/SC (`tests/security_card.py`):

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
[12] Cryptographic Hardening & Low-Order Point Defense...... [SW: 9000]
============================================================
  ALL 12 HARDWARE SECURITY TESTS PASSED 100% ON J3R452!
============================================================
```

**Multi-Algorithm Physical Card Verification**:
- `tests/security_card.py`: Ed25519 & X25519 KeyGen, EdDSA sign, ECDH decipher, low-order point defenses -> **12/12 PASSED**
- `tests/test_nistp256.py`: NIST P-256 (ansix9p256r1) On-Card KeyGen & ECDSA SHA-256 signing (66-byte DER) -> **PASSED [SW: 9000]**
- `tests/test_rsa.py`: RSA 2048 CRT On-Card KeyGen & PKCS#1 v1.5 signing (256-byte) -> **PASSED [SW: 9000]**

Verified via system `gpg --card-status`:
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

#### Manual Command-Line Installation:
```cmd
:: 1. Load the Curve25519 hardware driver CAP (AID: FF00025519)
gp -r PCD --load lib\Curve25519.cap

:: 2. Install and instantiate the SmartPGP Applet
gp -r PCD --install dist\SmartPGPApplet.cap

:: 3. Verify on card
gp -r PCD -l
```

#### One-Click Installation:
Run `install.bat` (or `./install.ps1` in PowerShell) for automated deployment with JVM entropy pre-warming (preventing Windows SCardSvr 5s timeouts).

---

### ⚙️ 6. Building from Source

**Prerequisites**: JDK 11 and Python 3 (or Apache Ant 1.10+).

```cmd
build.bat
```
*(PowerShell users can execute `./build.ps1`)*.

The build script compiles JavaCard bytecode against Oracle Java Card SDK 3.0.5/3.1.0, executes the Oracle Converter, and performs bytecode verification.

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
# Enter your PINs when prompted to generate native on-card keypairs
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

### 🛡️ 3. 密码学安全与深度加固

1. **恒定时间执行（防时序与功耗侧信道）**：
   - 标量乘法与 EdDSA 签名运算完全交由 NXP 芯片内部通过 CC EAL6+ 认证的硬件密码协处理器执行。
   - Java 代码中的所有 `if-else` 分支**严格属于公开元数据与指令路由**（例如算法选择或长度校验），绝对不存在任何依赖私钥内容、明文或中间状态的数据分支。
   - AES-128/256 CMAC 移位与子密钥约减消除 Java 层秘密相关分支，严密处理空尾块与跨包分段。
2. **RFC 7748 §6 全零共享秘密与低阶点防御**：
   - 对 X25519 ECDH 输出实施恒定时间全零检测，一旦协商结果全零或遭遇异常低阶点输入，立即擦除临时缓冲并拒绝返回，杜绝子群限制攻击。
3. **原子生命周期与掉电防撕裂保护 (Sentinel Flag)**：
   - 密钥槽使用持久有效状态及其反码标记。在密钥生成/导入过程中引入 EEPROM 状态哨兵，原生初始化与成对自检全部成功后才提交有效状态，掉电中断不会导致半成品密钥暴露为有效密钥。
4. **RFC 7748 与 RFC 8032 标量处理规范**：
   - X25519 私钥在导入时执行 RFC 7748 §5 标准标量钳位（Clamping）。
   - Ed25519 私钥严格保留为 32 字节原始 seed（RFC 8032），由底层硬件协处理器在 SHA-512 展开阶段内部完成标量推导与钳位，防止双重钳位破坏推导链。
5. **运行时签名校验与输出前自检验签**：
   - 对底层硬件协处理器返回的 Ed25519 签名执行严格的 64 字节长度断言（RFC 8032 §5.1.6）。
   - RSA、Ed25519、ECDSA 签名在发送 APDU 响应前均在片内执行验签自检，降低因瞬态故障或故障注入导致错误签名泄漏私钥的风险。ECDSA 签名输出固定宽度的裸 `r || s` 格式。
6. **敏感内存即时清零 (Zeroization)**：
   - 在 PIN/PUK 验证（`INS_VERIFY`、`INS_CHANGE_REFERENCE_DATA`、`INS_RESET_RETRY_COUNTER`）、`PUT DATA` 敏感属性写入以及密钥重置（`clearKey()`）路径中，主动清零 RAM 暂存缓冲与敏感持久槽位。
   - 卡片在断开或反选（Deselect）时，自动触发 `clearConnection()` 销毁所有会话密钥与 RAM 临时数据。
7. **密码引擎按需懒加载与零冗余复用架构**：
   - 为确保在多应用共存环境（如单卡同时部署 PIV、FIDO2、Satochip、Seedkeeper 与 VivoKey Apex OTP）下极限节约 JCOP 内存，SmartPGP 将单一 AES 引擎在应用主指令、安全信道（SM）及 CMAC 验签之间高度复用。
   - 占资源的复杂硬件密码引擎（RSA PKCS#1 密码机、标准 EC 椭圆曲线 Diffie-Hellman、SHA 散列族 ECDSA 签名器以及 Curve25519 引擎）均采用按需懒加载的静态单例模式。安装期静态密码对象由 15 个锐减至 2 个，使 JCOP 系统堆 RAM（Tag 03）可用空间翻倍，彻底消除 COR RAM 挤占冲突。
8. **双公钥格式原生兼容**：
   - 兼容原生 32 字节裸点及 RFC 4880bis / RFC 9580 规定的带 `0x40` 前缀的 33 字节公钥格式。

---

### 🧪 4. 物理卡片实机自动化测试报告

通过 PC/SC 在真实的 NXP J3R452 智能卡上运行 `tests/security_card.py` 自动化测试套件：

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
[12] 执行密码学加固与低阶点边界防御测试...................... [SW: 9000]
============================================================
  12 项硬件密码学安全测试全部 100% 通过！
============================================================
```

**多算法物理实机全覆盖验证**：
- `tests/security_card.py`：Ed25519 / X25519 密钥生成、EdDSA 签名、ECDH 硬件解密、零点/低阶点防护 -> **12 项全部通过**
- `tests/test_nistp256.py`：NIST P-256（ansix9p256r1）卡内密钥生成与 ECDSA SHA-256 签名（66 字节 DER） -> **实机通过 [SW: 9000]**
- `tests/test_rsa.py`：RSA 2048 CRT 卡内密钥生成与 PKCS#1 v1.5 填充签名（256 字节） -> **实机通过 [SW: 9000]**

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
*(PowerShell 用户可执行 `./install.ps1`)*

---

### ⚙️ 6. 源码构建说明

**前置依赖**：JDK 11 与 Python 3（或 Apache Ant 1.10+）。

```cmd
build.bat
```
*(PowerShell 用户可执行 `./build.ps1`)*。

构建脚本会自动调用 Java Card SDK 3.0.5/3.1.0 进行字节码编译、Oracle Converter 转换以及离线 Verifier 完整性校验。构建产物输出于：`dist/SmartPGPApplet.cap`。

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

### 📄 8. 开源许可证与致谢 (License & Credits)

本项目遵循 **GNU General Public License v2 (GPL-2.0)** 开源许可证协议 - 详见 [LICENSE](LICENSE) 文件。

- **[github-af/SmartPGP](https://github.com/github-af/SmartPGP)** & **[ANSSI-FR/SmartPGP](https://github.com/ANSSI-FR/SmartPGP)**: 原始 Java Card OpenPGP v3.4 规范实现 © ANSSI 及 SmartPGP 开源贡献者。
- **[suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)**: NXP J3R452 底层硬件 Curve25519 协处理器驱动库 © suut。
