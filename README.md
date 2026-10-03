# SmartPGP for NXP JCOP 4.5 / J3R452 (Hardware Curve25519)

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](LICENSE)
[![JavaCard](https://img.shields.io/badge/JavaCard-3.0.5-orange.svg)]()
[![Hardware](https://img.shields.io/badge/NXP-J3R452%20%2F%20JCOP%204.5-red.svg)]()
[![Hardware Crypto](https://img.shields.io/badge/Hardware%20Crypto-Ed25519%20%2F%20X25519-green.svg)]()
[![Tests](https://img.shields.io/badge/On%20Card%20Regression-PASSED-brightgreen.svg)]()

[English](#english) | [中文说明](#中文说明)

---

<a name="english"></a>
## English Documentation

### 📖 1. Project Background & Upstream Origins

This repository delivers a hardware-accelerated **OpenPGP Smart Card v3.4** implementation specifically engineered for **NXP JCOP 4.5 / J3R452** (P71D600 family) smart cards.

This project bridges and unifies two crucial open-source foundations:

1. **[github-af/SmartPGP](https://github.com/github-af/SmartPGP)** (and upstream [ANSSI-FR/SmartPGP](https://github.com/ANSSI-FR/SmartPGP)):
   - **Role**: Provides the robust high-level application architecture for the **OpenPGP Smart Card Specification v3.4**.
   - Handles all OpenPGP APDUs, data objects (DO), PW1 user modes, resetting code and PW3 administrator verification, cryptographic key slots (Signature, Decryption, Authentication), SCP11b Secure Messaging, and lifecycle management.
   - *Upstream Limitation*: Official SmartPGP only supported RSA and standard Weierstrass curves (via standard Java Card `javacard.security` APIs), lacking Curve25519 on Java Card 3.0.5 platforms.

2. **[suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)**:
   - **Role**: Provides the low-level on-card hardware cryptographic wrapper package (AID: `FF00025519`) specifically written for the NXP J3R452 / JCOP 4.5 family.
   - Unlocks NXP's private, proprietary hardware coprocessor package (`D276000085304A434F5058 v1.24`) to execute Ed25519 and X25519 on-card. Platform certification does not automatically certify this applet or wrapper.
   - Handles public-key and signature byte-order translations (bridging NXP SecAPI with RFC 7748 and RFC 8032).
   - *Upstream Limitation*: It is purely a low-level cryptographic driver library without any OpenPGP application protocol logic.

#### The Problem Solved by This Project
The target JCOP configuration exposes **Java Card 3.0.5** and vendor-specific 25519 services. This project uses the wrapper rather than requiring the standard XEC APIs introduced with Java Card 3.1; support still depends on the card OS/modules.

**This project seamlessly integrates `suut/Curve25519-JavaCard` into `github-af/SmartPGP`**, delivering native hardware-accelerated **Ed25519** (signing/authentication) and **X25519** (decryption) alongside RSA and Weierstrass curve support.

---

### 🌟 2. Key Capabilities & Performance

| Capability | Supported Specification | Execution / reference timing |
| :--- | :--- | :--- |
| **Hardware Ed25519** | RFC 8032 (`1.3.6.1.4.1.11591.15.1`, Algorithm `0x16`) | Wrapper reference: ~220 ms; excludes applet self-verification |
| **Hardware X25519** | RFC 7748 (`1.3.6.1.4.1.3029.1.5.1`, Algorithm `0x12`) | Wrapper reference: ~50 ms; not a release latency guarantee |
| **Legacy RSA** | RSA 2048, 3072, 4096 CRT with PKCS#1 v1.5 | Hardware accelerated |
| **Weierstrass EC** | NIST P-256/384/521, Brainpool P-256/384/512 | Hardware accelerated |
| **OpenPGP Spec** | OpenPGP Smart Card Specification v3.4 | GnuPG OpenPGP-card workflow; check client algorithm support |
| **Use Cases** | Git commit signing, file decryption, SSH auth (`gpg-agent`) | Through compatible host software |

---

### RSA private-key import (since package 1.2)

RSA-3072/4096 format-3 imports now stream one component at a time into a key that remains unavailable until all seven components and pairwise checks succeed. This reuses the 1280-byte work buffer and adds 16 bytes of transient parsing state; other applets do not need to be removed for this implementation.

Use the existing plaintext OpenPGP PUT DATA command/chaining on a contact interface, or on NFC with compatibility profile `00`. Large imports wrapped in SCP11b are **not** supported by this streaming path; the protected-command buffer limit is unchanged. This is not an invitation to bypass the strict NFC profile. Existing Ed25519/X25519 and RSA-2048 imports keep their complete-buffer validation path.

Malformed metadata is rejected before replacing the old key. Once a valid import starts writing key components, an error, interruption or reset makes the target slot unavailable; it does not restore the old private key. Re-import is the recovery path. Independent on-card tests cover import/readback/sign/decrypt/auth, malformed input, truncation, pair mismatch, reselection and reset at an APDU boundary. They do not establish arbitrary power-cut/fault-injection resistance.

### Package 1.3 review follow-up

The whole applet and build/install path were re-reviewed, including unchanged code. The follow-up fixes bound old-credential/new-PIN lengths before calling OwnerPIN; scan exactly one final AES block for ISO padding without plaintext-dependent loop termination; validate imported/ECDH public point form; recover incomplete SM key allocation; and correct certificate selection and cleanup. The padding check still returns valid/invalid and a decoded length; this is not a claim of physical constant time.

`tests/test_review_primitives.py` executes the actual Java padding/PIN helpers against reference results. `tests/security_review_card.py` exercises PIN/PUK boundaries, authorization, certificate selection, ECDH rejection, SM rekeying, all padding lengths and malformed authenticated padding/MACs. This suite changes PINs and provisions SM test keys, so use a disposable instance and reinstall afterwards. It does not replace power/EM/fault measurements or verify the closed native implementation.

### 🛡️ 3. Cryptographic Security & Hardening Highlights

1. **Hardware Delegation & Java-Level Branch Reduction**:
   - Scalar multiplication and EdDSA signing use the NXP services exposed by the wrapper.
   - CMAC subkey reduction and shifting avoid Java-level branches on secret-derived bits. This is not a proof of constant-time or leakage-free execution on the card.
   - CMAC streaming tests cover block boundaries and empty final input. Physical power/EM and fault-injection evaluation has not been completed.
2. **RFC 7748 §6 Zero Shared Secret & Small-Subgroup Detection**:
   - Uses a full-length OR accumulation to detect a zero shared secret on X25519 ECDH calculations.
   - Normalizes public X25519 inputs and rejects an all-zero shared secret, clearing the working buffer on failure.
3. **Atomic Key Lifecycle & Tear Protection (Sentinel Pattern)**:
   - Curve25519 key slots use persistent valid status flags and bitwise inverse validation.
   - Key generation and import flows are guarded by an EEPROM sentinel flag pattern, designed to keep incomplete keys unavailable until initialization and pairwise checks finish. Arbitrary power-cut and physical fault resistance still require measurement.
4. **RFC 7748 / RFC 8032 Scalar Clamping vs. Seed Preservation**:
   - Legacy OpenPGP X25519 imports use a big-endian private scalar, with the clamp applied to the corresponding bytes; public keys and shared secrets are little-endian.
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
   - Heavy cryptographic engines (RSA PKCS#1 ciphers, Weierstrass EC Diffie-Hellman, SHA-variant ECDSA signers, and Curve25519 hardware engines) are lazy-loaded on-demand via cached singletons. This reduces eager allocation; available RAM and multi-applet compatibility remain card-configuration dependent.
8. **Dual Public Key Format Compatibility**:
   - Accepts both 32-byte raw public keys and 33-byte public keys prefixed with `0x40` in the supported legacy OpenPGP card encoding.

---

### 🧪 4. Physical Card Verification Results

The current tests use independent host cryptography rather than checking status words and output lengths alone:

- `tests/security_host.py`: RFC 4493 CMAC vectors, 124 split positions, byte-wise updates, clearing, and six EC domain-parameter checks.
- `tests/security_card.py`: Ed25519/X25519 generation and import, known answers, low-order inputs, authorization failures, six ECDSA curves, RSA-2048, AES, certificate/DO updates and SCP11b. The completed run had 86 checks, including repeated chaining checks.
- `tests/security_extended_card.py`: P-256 ECDH, RSA-3072/4096 signatures and RSA-2048 CRT import with independent verification.
- `tests/test_rsa_stream_parser.py`: executes the actual Java streaming parser on the host, covering fragmentation, every RSA-4096 truncation point and abort cleanup.
- `tests/security_rsa_stream_card.py`: destructive RSA-3072/4096 external-import and recovery tests; requires an exact expected applet AID.

```cmd
python tests/security_host.py
python tests/security_card.py --reader "YOUR EXACT READER NAME" --allow-key-replacement
python tests/security_extended_card.py --reader "YOUR EXACT READER NAME" --allow-key-replacement
```

The card suites overwrite keys and data and require a disposable test instance. Legacy `test_curve25519.py`, `test_nistp256.py` and `test_rsa.py` forward to the combined suite. P-256 signatures are fixed-width 64-byte `r || s`, not 66-byte DER. Test results do not establish physical side-channel resistance or an applet EAL6+ certification.

---

### 🚀 5. Flashing to Card with GlobalPlatformPro (`gp`)

> [!IMPORTANT]
> You **MUST** load `Curve25519.cap` first before installing `SmartPGPApplet.cap`. The card installer will reject the applet if the driver package (`FF00025519`) is missing.

#### Manual Command-Line Installation:
```cmd
:: 1. Load the Curve25519 hardware driver CAP (AID: FF00025519)
gp.exe -r PCD --load lib\Curve25519.cap

:: 2. Install and instantiate the SmartPGP Applet
gp.exe -r PCD --install dist\SmartPGPApplet.cap --params 00

:: 3. Verify on card
gp.exe -r PCD -l
```

#### One-Click Installation:
Run `install.bat --reader PCD` (or `./install.ps1 --reader PCD`). This installs only this applet and its missing wrapper; replacing an existing instance requires `--replace-smartpgp` and erases its keys. Both installers select NFC compatibility (`00`) by default; `--strict-contactless` selects `01`, requiring SM for sensitive NFC commands. Installing manually without parameters retains the applet's strict default. These are generic single-applet installers, not a card-production tool.

---

### ⚙️ 6. Building from Source

**Prerequisites**: The pinned JDK 11.0.32.1+1 and Python 3.10+. Apache Ant is an optional entry point and still invokes Python.

```cmd
build.bat
```
*(PowerShell users can execute `./build.ps1`)*.

The build script compiles committed inputs twice using the pinned JDK/SDK, normalizes only archive timestamps/metadata, and independently verifies both resulting CAP files. It publishes only when the entire files are byte-for-byte identical. See [Reproducible builds](REPRODUCIBLE-BUILD.md) for the toolchain, source-commit binding and `--check-release`.

Output binary: `dist/SmartPGPApplet.cap`; identical copy: `prebuilt/SmartPGPApplet.cap`. The exact file identity is published in `dist/SHA256SUMS`.

The applet source is available, but the current Curve25519 wrapper is a pinned prebuilt dependency whose full implementation source is not published upstream. This is not a claim that the whole card stack is fully open source.

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

本项目是针对 **NXP JCOP 4.5 / J3R452**（P71D600 系列）智能卡、集成硬件密码服务的 **OpenPGP 智能卡 v3.4** 实现方案。

本项目融合并深度重构了两个优秀的开源项目：

1. **[github-af/SmartPGP](https://github.com/github-af/SmartPGP)**（源自 [ANSSI-FR/SmartPGP](https://github.com/ANSSI-FR/SmartPGP)）：
   - **承担角色**：提供完整的 **OpenPGP Smart Card 规范 v3.4** 应用层协议栈。
   - 负责处理全部 OpenPGP APDU 指令、数据对象（DO）、PIN 校验（PW1 用户模式、重置码、PW3 管理员密码）、三大密钥槽位（签名 SIG、解密 DEC、认证 AUT）、SCP11b 安全信道及生命周期管理。
   - *上游局限*：官方原版仅支持通过 Java Card 官方标准 API 实现的 RSA 与标准 Weierstrass 曲线（NIST / Brainpool），无法在 Java Card 3.0.5 平台使用硬件 Curve25519。

2. **[suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)**：
   - **承担角色**：提供专为 NXP J3R452 / JCOP 4.5 系列智能卡编写的底层硬件密码加速驱动包（AID: `FF00025519`）。
   - 接入并解锁了 NXP 原厂未公开的硬件协处理器私有接口（`D276000085304A434F5058 v1.24`），提供卡内 Ed25519 签名与 X25519 密钥协商。平台认证不会自动覆盖此包装库和本 applet。
   - 在底层实现透明的大小端序转换，使 NXP 协处理器与 RFC 7748、RFC 8032 标准无缝对接。
   - *上游局限*：仅为纯底层驱动库，不含任何 OpenPGP 应用层规范与指令交互逻辑。

#### 本项目解决的核心痛点
目标 JCOP 配置提供 **Java Card 3.0.5** 及厂商私有 25519 服务。本项目通过包装库使用这些服务，不要求 Java Card 3.1 新增的标准 XEC 接口；实际可用性仍取决于卡片 OS 和模块配置。

**本项目成功桥接了两大开源基石**：在 `github-af/SmartPGP` 中深度集成 `suut/Curve25519-JavaCard` 驱动，既实现了原生硬件级极速 **Ed25519**（签名/SSH认证）与 **X25519**（解密），并保留 RSA（2048/3072/4096）与标准椭圆曲线支持。

---

### 🌟 2. 核心特性与实测性能

| 功能模块 | 支持规格 | 执行方式／参考耗时 |
| :--- | :--- | :--- |
| **硬件 Ed25519** | RFC 8032（OID: `1.3.6.1.4.1.11591.15.1`，算法代号 `0x16`） | 包装库参考约 220 ms；不含 applet 自验签 |
| **硬件 X25519** | RFC 7748（OID: `1.3.6.1.4.1.3029.1.5.1`，算法代号 `0x12`） | 包装库参考约 50 ms；不保证本版本总耗时 |
| **经典 RSA** | RSA 2048, 3072, 4096 CRT (带 PKCS#1 v1.5 填充) | 硬件加速 |
| **Weierstrass EC** | NIST P-256/384/521, Brainpool P-256/384/512 | 硬件加速 |
| **OpenPGP 规范** | OpenPGP Smart Card 规范 v3.4 | 适用于 GnuPG OpenPGP 卡工作流，需客户端支持相应算法 |
| **应用场景** | Git 提交签名、邮件与文件加解密、SSH 密钥认证 | 通过兼容的主机客户端使用 |

---

### RSA 私钥导入（自包版本 1.2）

RSA-3072/4096 的格式3导入现在逐个分量写入密钥对象，全部七个分量及成对检查成功后才允许使用。复用原1280字节工作缓冲，只增加16字节瞬态解析状态，不要求为此删除其他应用。

适用于接触接口的普通 OpenPGP PUT DATA/命令链，以及兼容profile `00`下的NFC。**封装在SCP11b中的大RSA导入不走这条流式路径**，受保护命令仍有原缓冲上限；不得因此绕开严格NFC策略。Ed25519/X25519与RSA-2048仍使用完整缓冲后的原解析验证路径。

错误模板在替换旧钥前拒绝；开始写入有效导入的分量之后，异常、中断或复位会令目标槽不可用，不承诺恢复旧私钥，重新导入即可恢复。独立实卡测试包含导入/公钥读回/签名/解密/认证、恶意输入、截断、公私钥不匹配、重选及APDU边界上的受控复位；不等于任意时点断电或物理故障注入评估。

### 包版本 1.3 全量复审后修复

重新审查了整个app及构建/安装路径，包含未修改代码。新增修复：在OwnerPIN验证之前检查“旧凭据＋新PIN”完整长度；对ISO填充固定扫描最后一个AES块，避免按解密内容提前结束；检查导入/ECDH公钥格式；恢复SM会话密钥部分分配失败；修正证书选择状态及清理。填充验证仍返回合法/非法及内容长度，不将此称为物理恒时证明。

`tests/test_review_primitives.py`直接执行Java填充/PIN辅助函数，与参考结果对照。`tests/security_review_card.py`覆盖PIN/PUK边界、权限、证书选择、非法ECDH、SM重建、全部填充长度及携带有效MAC的非法填充。该套件会改测试PIN并配置SM测试钥，仅用于可重装实例，结束后需清洁重装；不能替代功耗/EM/故障测量或证明不透明原生实现安全。

### 🛡️ 3. 密码学安全与深度加固

1. **硬件密码服务与 Java 层分支减少**：
   - 标量乘法与 EdDSA 签名通过包装库使用 NXP 卡内密码服务。
   - CMAC 子密钥约减与移位避免依赖秘密派生位的 Java 条件分支；这不能单独证明原生实现恒时或无物理泄漏。
   - AES-128/256 CMAC 移位与子密钥约减消除 Java 层秘密相关分支，处理空尾块与分段边界，并有独立向量验证。本项目尚未完成物理功耗／EM／故障注入评估。
2. **RFC 7748 §6 全零共享秘密与低阶点防御**：
   - 对 X25519 公开输入规范化；遍历全部输出字节作 OR 聚合，检测全零共享秘密并拒绝，失败时清理工作缓冲。
3. **原子生命周期与掉电防撕裂保护 (Sentinel Flag)**：
   - 密钥槽使用持久有效状态及其反码标记。在密钥生成/导入过程中引入 EEPROM 状态哨兵，原生初始化与成对自检全部成功后才提交有效状态，设计目标是让未完成更新的密钥保持不可用；任意时点掉电和物理故障抵抗力仍需实测。
4. **RFC 7748 与 RFC 8032 标量处理规范**：
   - Legacy OpenPGP X25519 导入私钥为大端整数，在对应首尾字节执行钳位；公钥和共享秘密采用小端编码。
   - Ed25519 私钥严格保留为 32 字节原始 seed（RFC 8032），由底层硬件协处理器在 SHA-512 展开阶段内部完成标量推导与钳位，防止双重钳位破坏推导链。
5. **运行时签名校验与输出前自检验签**：
   - 对底层硬件协处理器返回的 Ed25519 签名执行严格的 64 字节长度断言（RFC 8032 §5.1.6）。
   - RSA、Ed25519、ECDSA 签名在发送 APDU 响应前均在片内执行验签自检，降低因瞬态故障或故障注入导致错误签名泄漏私钥的风险。ECDSA 签名输出固定宽度的裸 `r || s` 格式。
6. **敏感内存即时清零 (Zeroization)**：
   - 在 PIN/PUK 验证（`INS_VERIFY`、`INS_CHANGE_REFERENCE_DATA`、`INS_RESET_RETRY_COUNTER`）、`PUT DATA` 敏感属性写入以及密钥重置（`clearKey()`）路径中，主动清零 RAM 暂存缓冲与敏感持久槽位。
   - 卡片在断开或反选（Deselect）时，自动触发 `clearConnection()` 销毁所有会话密钥与 RAM 临时数据。
7. **密码引擎按需懒加载与零冗余复用架构**：
   - 为确保在多应用共存环境（如单卡同时部署 PIV、FIDO2、Satochip、Seedkeeper 与 VivoKey Apex OTP）下极限节约 JCOP 内存，SmartPGP 将单一 AES 引擎在应用主指令、安全信道（SM）及 CMAC 验签之间高度复用。
   - 占资源的复杂硬件密码引擎（RSA PKCS#1 密码机、标准 EC 椭圆曲线 Diffie-Hellman、SHA 散列族 ECDSA 签名器以及 Curve25519 引擎）均采用按需懒加载的静态单例模式。这样可以减少提前分配；多应用共存的 RAM 余量仍需针对实际卡配置验证。
8. **双公钥格式原生兼容**：
   - 支持对应 legacy OpenPGP 卡编码的 32 字节裸公钥和带 `0x40` 前缀的 33 字节公钥。

---

### 🧪 4. 物理卡片实机自动化测试报告

当前测试通过独立主机密码库验证结果，不只检查状态字和长度：

- `tests/security_host.py`：RFC 4493 CMAC 向量、124 种分段、逐字节更新、清理及六条曲线的基本参数检查。
- `tests/security_card.py`：Ed25519/X25519 生成和导入、已知答案、低阶输入、权限负测试、六条 ECDSA 曲线、RSA-2048、AES、证书／DO 更新与 SCP11b。已完成的运行包含 86 条检查，其中有重复的命令链分片检查。
- `tests/security_extended_card.py`：P-256 ECDH、RSA-3072/4096 签名和 RSA-2048 CRT 导入，均采用独立结果校验。
- `tests/test_rsa_stream_parser.py`：主机上执行实际Java流式解析器，覆盖分片、RSA-4096全部截断位置及异常清理。
- `tests/security_rsa_stream_card.py`：RSA-3072/4096外部导入与恢复的破坏性实卡测试，要求明确预期实例AID。

```cmd
python tests/security_host.py
python tests/security_card.py --reader "准确的读卡器名称" --allow-key-replacement
python tests/security_extended_card.py --reader "准确的读卡器名称" --allow-key-replacement
```

卡上测试会覆盖密钥和数据，仅用于可重置测试实例。旧 `test_curve25519.py`、`test_nistp256.py`、`test_rsa.py` 入口转发到统一套件。P-256 输出是固定 64 字节 `r || s`，不是“66 字节 DER”。这些结果不代表 applet 获得 EAL6+ 认证或完成物理侧信道评估。

---

### 🚀 5. 使用 GlobalPlatformPro (`gp`) 刷卡指南

> [!IMPORTANT]
> 必须**先 `--load` 硬件驱动库，再 `--install` Applet**。若缺少底层依赖包 `FF00025519`，卡片会直接拒绝安装。

#### 命令行手动刷写：
```cmd
:: 第一步：载入底层 Curve25519 硬件驱动库 (AID: FF00025519)
gp.exe -r PCD --load lib\Curve25519.cap

:: 第二步：安装并实例化 SmartPGP Applet
gp.exe -r PCD --install dist\SmartPGPApplet.cap --params 00

:: 第三步：查看卡片状态确认就绪
gp.exe -r PCD -l
```

#### 单 applet 安装脚本：
```cmd
install.bat --reader PCD
```
*(PowerShell 用户可执行 `./install.ps1 --reader PCD`)*

---

### ⚙️ 6. 源码构建说明

**前置依赖**：锁文件规定的 JDK 11.0.32.1+1 与 Python 3.10+。Apache Ant 是可选入口，仍会调用 Python 构建器。

```cmd
build.bat
```
*(PowerShell 用户可执行 `./build.ps1`)*。

构建器使用已提交源码和锁定工具链独立构建两次，规范化归档时间戳，并校验最终CAP；仅当整个文件字节完全一致才更新 `dist` 和 `prebuilt`。详见[可复现构建说明](REPRODUCIBLE-BUILD.md)，用户可用 `--check-release` 重新编译核对公开成品。整体文件哈希发布在 `dist/SHA256SUMS`。

本仓库的SmartPGP applet源码可重建，但当前Curve25519包装库仍是固定哈希的预编译依赖，上游未公开完整实现；不能把这等同于整张卡和全部依赖100%开源。

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
