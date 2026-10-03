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

This repository delivers a hardware-accelerated, cryptographically audited **OpenPGP Smart Card v3.4** implementation specifically engineered for **NXP JCOP 4.5 / J3R452** (P71D600 family) smart cards.

This project bridges and unifies two crucial open-source foundations:

1. **[github-af/SmartPGP](https://github.com/github-af/SmartPGP)** (and upstream [ANSSI-FR/SmartPGP](https://github.com/ANSSI-FR/SmartPGP)):
   - **Role**: Provides the robust high-level application architecture for the **OpenPGP Smart Card Specification v3.4**.
   - Handles all OpenPGP APDUs, data objects (DO), PW1 user modes, resetting code and PW3 administrator verification, cryptographic key slots (Signature, Decryption, Authentication), SCP11b Secure Messaging, and lifecycle management.
   - *Upstream Limitation*: Official SmartPGP only supported RSA and standard Weierstrass curves (via standard Java Card `javacard.security` APIs), lacking Curve25519 on Java Card 3.0.5 platforms.

2. **[suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)**:
   - **Role**: Provides the low-level on-card hardware cryptographic wrapper package (AID: `FF00025519`) specifically written for the NXP J3R452 / JCOP 4.5 family.
   - Unlocks NXP's private, proprietary hardware coprocessor package (`D276000085304A434F5058 v1.24`) to execute Ed25519 and X25519 directly in silicon.
   - Handles transparent public-key and signature byte-order translations (bridging NXP SecAPI with RFC 7748 and RFC 8032).
   - *Upstream Limitation*: It is purely a low-level cryptographic driver library without any OpenPGP application protocol logic.

#### The Problem Solved by This Project
The target JCOP configuration exposes **Java Card 3.0.5** and vendor-specific 25519 services. Standard Java Card 3.1 APIs (`NamedParameterSpec.X25519`, `buildXECKey`) throw `NO_SUCH_ALGORITHM`. 

**This project seamlessly integrates `suut/Curve25519-JavaCard` into `github-af/SmartPGP`**, delivering native hardware-accelerated **Ed25519** (signing/authentication) and **X25519** (decryption) alongside full RSA and Weierstrass curve support.

---

### 🌟 2. Key Capabilities & Performance

| Capability | Supported Specification | Execution & Reference Timing |
| :--- | :--- | :--- |
| **Hardware Ed25519** | RFC 8032 (`1.3.6.1.4.1.11591.15.1`, Algorithm `0x16`) | ~220 ms per signature |
| **Hardware X25519** | RFC 7748 (`1.3.6.1.4.1.3029.1.5.1`, Algorithm `0x12`) | ~50 ms per key agreement |
| **Legacy RSA** | RSA 2048, 3072, 4096 CRT with PKCS#1 v1.5 | Hardware accelerated |
| **Weierstrass EC** | NIST P-256/384/521, Brainpool P-256/384/512 | Hardware accelerated |
| **OpenPGP Spec** | OpenPGP Smart Card Specification v3.4 | Compatible with GnuPG 2.2 / 2.3 / 2.4 / 2.5+ |
| **Use Cases** | Git commit signing, file decryption, SSH auth (`gpg-agent`) | 100% plug-and-play via compatible host clients |

#### Streaming RSA 3072 / 4096 Private Key Import
Starting from package version 1.2, large RSA private keys (3072 and 4096 bits, format 3) are imported via a component-by-component streaming parser. Key components are written directly into persistent storage while strictly reusing the existing 1280-byte APDU work buffer and requiring only 16 bytes of transient state. The key slot remains unavailable until all seven CRT components are completely transferred and verified via on-chip pairwise consistency checks. This avoids large RAM allocations and preserves memory for cards co-hosting multiple applets (e.g., FIDO2, PIV, Satochip).

---

### 🛡️ 3. Cryptographic Security & Hardening Highlights

1. **Native Hardware CMAC Service (v1.4+)**:
   - Secure Messaging (SCP11b) utilizes the on-chip hardware `Signature.ALG_AES_CMAC_128` engine.
   - Eliminates Java-level derivation and storage of K1/K2 subkeys and manual chaining loops, removing application-level secret data handling.
   - Operates in a fail-closed manner: if the card platform lacks the native CMAC engine, session negotiation is rejected rather than silently degrading to insecure software branches.
2. **Constant-Time Execution & Secure SM Padding (v1.3+)**:
   - Scalar multiplication and EdDSA signing execute directly inside the CC EAL6+ certified hardware engine.
   - Java code branches strictly on public metadata and command routing; no branching depends on secret bits or plaintexts.
   - Secure Messaging ISO 7816-4 padding verification performs a constant-boundary scan over exactly the final 16-byte AES block without early loop exits based on plaintext content, cleanly handling empty plaintext payloads.
3. **RFC 7748 §6 Zero Shared Secret & Small-Subgroup Detection**:
   - Enforces constant-time zero shared secret detection across all 32 bytes on X25519 ECDH calculations.
   - Normalizes public points according to RFC 7748 (clamping high bits and reducing non-canonical coordinates).
   - If the shared secret is all zeros or maps to a small-subgroup root, transient buffers are scrubbed immediately and the operation is rejected (`SW_CONDITIONS_NOT_SATISFIED`).
4. **Atomic Key Lifecycle & Tear Protection (Sentinel Pattern)**:
   - Curve25519 key slots use persistent valid status flags and bitwise inverse validation.
   - Key generation and import flows are guarded by an EEPROM sentinel flag pattern (`key_operation_in_progress`), ensuring that sudden power loss or card tearing during generation cannot leave half-written keys in an active state.
5. **RFC 7748 / RFC 8032 Scalar Clamping vs. Seed Preservation**:
   - Imported X25519 private keys undergo standard RFC 7748 §5 scalar clamping at the application layer.
   - Ed25519 private keys are preserved as raw 32-byte seeds per RFC 8032, allowing the underlying hardware engine to perform SHA-512 expansion and clamping internally, avoiding double-clamping errors.
6. **Pre-Validation of PIN/PUK Bounds (v1.3+)**:
   - The total length and structure of credential modification commands (old credential + new PIN) are strictly validated before delegating to `OwnerPIN.check()`.
   - Prevents truncated or malformed APDUs from erroneously decrementing PW1, PW3, or PUK retry counters.
7. **Runtime Signature Validation & Pre-Output Self-Verification**:
   - Enforces runtime assertions verifying that Ed25519 signatures returned from the hardware coprocessor are exactly 64 bytes (RFC 8032 §5.1.6).
   - Signatures (RSA, Ed25519, ECDSA) undergo on-chip verification prior to returning the APDU response, protecting against physical or fault-injection attacks that could leak private keys through erroneous signatures.
   - ECDSA signatures return fixed-width raw `r || s` (64 bytes for P-256, 96 bytes for P-384, 132 bytes for P-521).
8. **Immediate Sensitive Memory Zeroization**:
   - Transient RAM buffers are proactively scrubbed across PIN/PUK verification (`INS_VERIFY`, `INS_CHANGE_REFERENCE_DATA`, `INS_RESET_RETRY_COUNTER`), `PUT DATA` operations, and key deletion (`clearKey()`).
   - Upon applet deselect or connection reset, all transient session buffers and session keys are destroyed.
9. **Lazy-Loaded Engines & System RAM Optimization**:
   - Shares an AES-CBC cipher across the core AES service and SCP11b encryption; an on-demand native CMAC Signature object handles MAC verification.
   - Heavy cryptographic engines are lazy-loaded via cached singletons, keeping static crypto objects at installation to 2, conserving critical JCOP System RAM (Tag 03) and eliminating COR RAM allocation conflicts.
10. **Dual Public Key Format Compatibility**:
    - Transparently accepts both 32-byte raw public keys and 33-byte public keys prefixed with `0x40` (RFC 4880bis / RFC 9580).

---

### 🧪 4. Physical Card & Test Suites Verification

The repository includes a comprehensive, multi-layer verification suite utilizing independent host cryptography:

- `tests/security_host.py`: Offline regression covering the native CMAC adapter with independent AES-128/256 references, 772 split/truncation cases, byte/short updates, failure cleanup, and 6 EC curve domain parameters.
- `tests/security_card.py`: Physical card test suite executing 86 checks including Ed25519/X25519 keygen/import, known-answer tests, low-order point handling, PIN authorization failures, 6 ECDSA curves, RSA-2048, and SCP11b.
- `tests/security_rsa_stream_card.py`: 76 physical card checks validating RSA-3072/4096 streaming import, component readback, signing, deciphering, authentication, and abort recovery.
- `tests/security_review_card.py`: 86 on-card checks covering PIN/PUK boundaries, access controls, certificate slots, invalid ECDH point rejection, SM rekeying, and padding boundary tests.
- `tests/security_sm_curves_card.py`: 66 physical card checks covering SCP11b across all 6 supported curves and both AES-128 and AES-256 session keys.
- `tests/security_ed25519_boundaries.py`: 30 checks covering Ed25519 message boundary and buffer limit conditions.
- `tests/security_kdf_card.py`: 19 checks validating derived-PIN format transitions.
- `tests/security_extended_card.py`: 9 checks for P-256 ECDH, RSA-3072/4096 signatures, and RSA-2048 CRT import.
- `tests/test_reproducible_build.py` & `test_installer.py`: 30 offline unit tests covering deterministic compilation and installer verification.

```cmd
# Offline host regression tests (no card required):
python tests/security_host.py
python -m unittest discover -s tests -p "test_*.py" -v

# Physical on-card regression tests (requires card reader):
python tests/security_card.py --reader "YOUR EXACT READER NAME" --allow-key-replacement
python tests/security_rsa_stream_card.py --reader "YOUR EXACT READER NAME" --allow-key-replacement
python tests/security_review_card.py --reader "YOUR EXACT READER NAME" --allow-key-replacement
```

Verified via system `gpg --card-status`:
```text
Application ID ...: D276000124010304AFAF000000000000
Version ..........: 3.4
Key attributes ...: ed25519 cv25519 ed25519
Signature counter : 1
```

*Note: Software-level tests verify cryptographic correctness and protocol robustness; they do not replace formal hardware side-channel (SCA/TVLA) and fault-injection (FI) evaluations.*

---

### 🚀 5. Flashing to Card with GlobalPlatformPro (`gp`)

> [!IMPORTANT]
> You **MUST** load `Curve25519.cap` first before installing `SmartPGPApplet.cap`. The card installer will reject the applet if the driver package (`FF00025519`) is missing.

#### Manual Command-Line Installation:
```cmd
:: Step 1: Load the Curve25519 hardware driver CAP (AID: FF00025519)
gp.exe -r PCD --load lib\Curve25519.cap

:: Step 2: Install and instantiate SmartPGP Applet (NFC Compatibility Mode recommended)
gp.exe -r PCD --install dist\SmartPGPApplet.cap --params 00

:: Step 3: Verify applet status on card
gp.exe -r PCD -l
```

#### Installation Parameters & Contactless (NFC) Policies

The `--params` option passes installation arguments directly to the applet during `install()`:

| Parameter | Profile Name | Contactless (NFC) APDU Behavior |
| :--- | :--- | :--- |
| **`--params 00`** | **NFC Compatibility Mode** *(Recommended for Mobile)* | When Secure Messaging (SM) is not provisioned, allows PIN verification, key generation, key import, signing, and decryption over plain contactless NFC. |
| **`--params 01`** | **Strict Mode** | Sensitive operations over contactless NFC strictly require an established SCP11b Secure Messaging channel. Plaintext NFC sensitive APDUs are rejected (`SW: 6985`). |
| *(None)* | **Default (Strict)** | If `--params` is omitted, the applet defaults to Strict Mode (`01`). |

> [!NOTE]
> - **Security scope of `--params 00`**: Mode `00` does **not** bypass PIN authentication, does **not** weaken permission checks or retry limits, and does **not** alter GlobalPlatform keys. It solely controls whether contactless APDUs require SCP11b channel encryption.
> - **Automatic enforcement upon SM setup**: Even if installed with `--params 00`, once static Secure Messaging keys are provisioned on the card, the applet automatically enforces SM for all subsequent contactless sensitive operations.

#### One-Click Installation Script:
```cmd
install.bat --reader PCD
```
*(PowerShell users can execute `./install.ps1 --reader PCD`)*

The installer defaults to NFC Compatibility Mode (`--params 00`). Use `--strict-contactless` if you wish to enforce Strict Mode (`01`). Reinstalling over an existing applet instance requires the explicit `--replace-smartpgp` flag to prevent accidental data loss.

---

### ⚙️ 6. Building from Source & Reproducible Builds

**Prerequisites**: Pinned JDK 11.0.32.1+1 and Python 3.10+.

```cmd
build.bat
```
*(PowerShell users can execute `./build.ps1`)*.

The build system utilizes a deterministic pipeline: it compiles committed sources twice across isolated environments, normalizes ZIP container timestamps and metadata, and performs Oracle off-card bytecode verification. The resulting CAP binary is byte-for-byte reproducible.

Output binary: `dist/SmartPGPApplet.cap` (SHA-256 verified in `dist/SHA256SUMS`).

To verify release integrity against the recorded source commit:
```powershell
python tools/verify_release.py
```
For detailed toolchain specifications and independent rebuild instructions, see [REPRODUCIBLE-BUILD.md](REPRODUCIBLE-BUILD.md).

---

### 🔑 7. GnuPG Quick Start

- **Default User PIN (PW1)**: `123456`
- **Default Admin PIN (PW3)**: `12345678`

```bash
# 1. Inspect card status
gpg --card-status

# 2. Configure Curve25519 keys
gpg --card-edit
gpg/card> admin
gpg/card> key-attr
# Select (2) ECC -> (1) Curve 25519 for Signature, Encryption, Authentication
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

本项目是专门针对 **NXP JCOP 4.5 / J3R452**（P71D600 系列）智能卡深度定制、通过严格密码学审计且集成硬件密码加速的 **OpenPGP 智能卡 v3.4** 实现方案。

本项目融合并深度重构了两个优秀的开源项目：

1. **[github-af/SmartPGP](https://github.com/github-af/SmartPGP)**（源自 [ANSSI-FR/SmartPGP](https://github.com/ANSSI-FR/SmartPGP)）：
   - **承担角色**：提供完整的 **OpenPGP Smart Card 规范 v3.4** 应用层协议栈。
   - 负责处理全部 OpenPGP APDU 指令、数据对象（DO）、PIN 校验（PW1 用户模式、重置码、PW3 管理员密码）、三大密钥槽位（签名 SIG、解密 DEC、认证 AUT）、SCP11b 安全信道及生命周期管理。
   - *上游局限*：官方原版仅支持通过 Java Card 官方标准 API 实现的 RSA 与标准 Weierstrass 曲线（NIST / Brainpool），无法在 Java Card 3.0.5 平台使用硬件 Curve25519。

2. **[suut/Curve25519-JavaCard](https://github.com/suut/Curve25519-JavaCard)**：
   - **承担角色**：提供专为 NXP J3R452 / JCOP 4.5 系列智能卡编写的底层硬件密码加速驱动包（AID: `FF00025519`）。
   - 接入并解锁了 NXP 原厂未公开的硬件协处理器私有接口（`D276000085304A434F5058 v1.24`），实现硅片级 Ed25519 签名与 X25519 密钥协商。
   - 在底层实现透明的大小端序转换，使 NXP 协处理器与 RFC 7748、RFC 8032 标准无缝对接。
   - *上游局限*：仅为纯底层驱动库，不含任何 OpenPGP 应用层规范与指令交互逻辑。

#### 本项目解决的核心痛点
NXP J3R452 智能卡运行 **Java Card 3.0.5** 规范，无法调用 Java Card 3.1 引入的标准 XECKey 接口（会抛出 `NO_SUCH_ALGORITHM`）。

**本项目成功桥接了两大开源基石**：在 `github-af/SmartPGP` 中深度集成 `suut/Curve25519-JavaCard` 驱动，既实现了原生硬件级极速 **Ed25519**（签名/SSH认证）与 **X25519**（解密），又完整保留了对 RSA（2048/3072/4096）与标准椭圆曲线的全部兼容性。

---

### 🌟 2. 核心特性与实测性能

| 功能模块 | 支持规格 | 执行方式与参考耗时 |
| :--- | :--- | :--- |
| **硬件 Ed25519** | RFC 8032（OID: `1.3.6.1.4.1.11591.15.1`，算法代号 `0x16`） | 约 **220 ms** / 次签名 |
| **硬件 X25519** | RFC 7748（OID: `1.3.6.1.4.1.3029.1.5.1`，算法代号 `0x12`） | 约 **50 ms** / 次密钥协商 |
| **经典 RSA** | RSA 2048, 3072, 4096 CRT (带 PKCS#1 v1.5 填充) | 硬件加速 |
| **Weierstrass EC** | NIST P-256/384/521, Brainpool P-256/384/512 | 硬件加速 |
| **OpenPGP 规范** | OpenPGP Smart Card 规范 v3.4 | 原生兼容 GnuPG 2.2 / 2.3 / 2.4 / 2.5+ |
| **应用场景** | Git 提交签名、邮件与文件加解密、SSH 密钥认证 | 100% 即插即用 |

#### RSA 3072 / 4096 私钥流式导入
自包版本 1.2 起，支持对大规格 RSA（3072 与 4096 位，格式 3）私钥进行流式分量导入。导入过程将各个分量逐个流式写入持久私钥对象中，严格复用原有的 1280 字节 APDU 工作缓冲，仅需占用 16 字节瞬态解析状态。只有在全部 7 个 CRT 分量完整写入且片内成对自检通过后，密钥槽位才置为可用状态；导入过程中断或异常会令槽位保持失效，杜绝半成品私钥被使用，同时大幅节约 RAM 资源，确保与 FIDO2、PIV、Satochip 等多应用顺畅共存。

---

### 🛡️ 3. 密码学安全与深度加固

1. **原生硬件 CMAC 服务 (v1.4+)**：
   - 安全消息（SCP11b）全面改用卡片原生 `Signature.ALG_AES_CMAC_128` 硬件引擎。
   - 彻底废除 Java 层的 K1/K2 子密钥派生和内存处理，避免应用层暴露秘密中间值。
   - 采用 Fail-Closed 机制：若平台缺少原生 CMAC 支持，直接拒绝建立会话，绝不静默降级为不安全的软件分支。
2. **恒定时间执行与安全 SM 填充 (v1.3+)**：
   - 标量乘法与 EdDSA 签名运算完全交由 NXP 芯片内部通过 CC EAL6+ 认证的硬件密码协处理器执行。
   - Java 代码中的所有条件分支严格属于公开元数据与指令路由，绝无依赖私钥或明文数据的分支。
   - 对 ISO 7816-4 填充实施**固定遍历最后一个 16 字节 AES 块**的常数边界检查，消除按明文内容提前退出循环的时序差异，正确处理合法的空内容明文。
3. **RFC 7748 §6 全零共享秘密与低阶点防御**：
   - 对 X25519 ECDH 协商输出实施全 32 字节恒定时间非零聚合检查。
   - 对公开输入执行 RFC 7748 规范化过滤（屏蔽最高位并约减非规范坐标）。
   - 一旦协商结果全零或遭遇异常低阶点输入，立即擦除临时工作缓冲并拒绝返回（`SW_CONDITIONS_NOT_SATISFIED`），杜绝小微子群限制攻击。
4. **原子生命周期与掉电防撕裂保护 (Sentinel Flag)**：
   - 密钥槽使用持久有效状态及其反码标记。在密钥生成/导入流程中引入 EEPROM 状态哨兵（`key_operation_in_progress`），原生初始化与成对自检全部成功后才原子提交有效状态，意外断电绝不会导致未完成密钥暴露为可用密钥。
5. **RFC 7748 与 RFC 8032 标量处理规范**：
   - X25519 私钥在导入时执行 RFC 7748 §5 标准标量钳位（Clamping）。
   - Ed25519 私钥严格保留为 32 字节原始 seed（RFC 8032），由底层协处理器在 SHA-512 展开阶段内部完成标量推导与钳位，防止双重钳位破坏密钥链。
6. **PIN / PUK 输入边界前置校验 (v1.3+)**：
   - 在调用底层 `OwnerPIN.check()` 之前，先严格校验凭据修改指令（旧凭据 + 新 PIN）的总长度与结构格式。
   - 杜绝恶意截断或格式非法的 APDU 意外消耗 PW1、PW3 或 PUK 的重试计数。
7. **运行时签名校验与输出前自检验签**：
   - 对底层协处理器返回的 Ed25519 签名执行严格的 64 字节长度断言（RFC 8032 §5.1.6）。
   - RSA、Ed25519、ECDSA 签名在发送 APDU 响应前均在片内执行验签自检，防止瞬态故障或故障注入攻击利用错误签名泄漏私钥。ECDSA 签名统一输出固定宽度的裸 `r || s` 格式。
8. **敏感内存即时清零 (Zeroization)**：
   - 在 PIN/PUK 验证（`INS_VERIFY`、`INS_CHANGE_REFERENCE_DATA`、`INS_RESET_RETRY_COUNTER`）、`PUT DATA` 敏感属性写入以及密钥重置（`clearKey()`）路径中，主动清零 RAM 暂存缓冲与敏感持久槽位。
   - 卡片在断开连接或反选（Deselect）时，自动销毁所有会话密钥与 RAM 临时数据。
9. **密码引擎按需懒加载与零冗余复用架构**：
   - 在应用主指令与 SCP11b 加密之间高度复用单一 AES-CBC 对象，按需分配原生 CMAC 验签对象。
   - 复杂硬件密码引擎均采用按需懒加载的静态单例模式，安装期静态密码对象由 15 个锐减至 2 个，最大限度节约 JCOP 系统堆 RAM（Tag 03），消除 COR RAM 分配冲突。
10. **双公钥格式原生兼容**：
    - 原生兼容 32 字节裸点及 RFC 4880bis / RFC 9580 规定的带 `0x40` 前缀的 33 字节公钥格式。

---

### 🧪 4. 物理卡片实机与自动化测试套件

仓库提供多层次的完备自动化测试体系，采用独立主机密码学进行端到端结果断言：

- `tests/security_host.py`：离线回归测试，覆盖原生 CMAC 适配器、AES-128/256 独立对照、772 种分段/截断组合、异常清理与 6 条椭圆曲线数学参数验证。
- `tests/security_card.py`：实卡主回归套件，执行 86 项全链路检查，包含 Ed25519/X25519 密钥生成与导入、已知答案测试、低阶点防御、PIN 权限负测试、6 条 ECDSA 曲线、RSA-2048 及 SCP11b 链路。
- `tests/security_rsa_stream_card.py`：76 项实卡检查，严格测试 RSA-3072/4096 流式导入、分量读回、签名、解密、认证及中断恢复。
- `tests/security_review_card.py`：86 项实卡检查，专门覆盖 PIN/PUK 边界、权限控制、证书槽选择、非法 ECDH 点拒绝、安全消息重建及全填充边界。
- `tests/security_sm_curves_card.py`：66 项实卡检查，验证全部 6 条曲线的 SCP11b 协商与 AES-128/256 会话。
- `tests/security_ed25519_boundaries.py`：30 项实卡检查，覆盖 Ed25519 极端消息边界与缓冲区极限。
- `tests/security_kdf_card.py`：19 项实卡检查，验证卡侧 32/64 字节派生 PIN 格式迁移。
- `tests/security_extended_card.py`：9 项扩展实卡测试（P-256 ECDH、RSA-3072/4096 验签等）。
- `tests/test_reproducible_build.py` & `test_installer.py`：30 项离线单元测试，覆盖确定性编译与安装校验。

```cmd
# 1. 运行离线算法回归测试（无需插卡）：
python tests/security_host.py
python -m unittest discover -s tests -p "test_*.py" -v

# 2. 运行物理实卡回归测试（需接读卡器）：
python tests/security_card.py --reader "准确的读卡器名称" --allow-key-replacement
python tests/security_rsa_stream_card.py --reader "准确的读卡器名称" --allow-key-replacement
python tests/security_review_card.py --reader "准确的读卡器名称" --allow-key-replacement
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
gp.exe -r PCD --load lib\Curve25519.cap

:: 第二步：安装并实例化 SmartPGP Applet（推荐使用 NFC 兼容参数 00）
gp.exe -r PCD --install dist\SmartPGPApplet.cap --params 00

:: 第三步：查看卡片状态确认就绪
gp.exe -r PCD -l
```

#### 安装参数与非接触 (NFC) 安全策略详解

`--params` 是在安装（`install()`）时传递给 SmartPGP 的应用层配置参数：

| 安装参数 | 策略模式 | 非接触 (NFC) 交互行为 |
| :--- | :--- | :--- |
| **`--params 00`** | **NFC 兼容模式** *(手机用户推荐)* | **未配置 SM 安全消息时，允许通过普通非接触 APDU 验证 PIN、生成/导入密钥、签名和解密。** 用户拿到卡后无需预先建立安全信道，即可使用手机 NFC 客户端直接操作。 |
| **`--params 01`** | **严格模式 (Strict)** | **非接触敏感操作必须强制建立 SCP11b 安全消息链路。** 若使用普通明文 NFC APDU 发送敏感指令，卡片将直接拒绝并返回 `SW: 6985`。 |
| *(不传参数)* | **默认严格模式** | 若安装时不带 `--params`，Applet 内部默认启用严格模式（等同于 `01`）。 |

> [!NOTE]
> - **`--params 00` 的安全边界**：兼容模式**不会**关闭 PIN 身份验证、**不会**放宽权限检查或重试次数、**不会**跳过密码学自检，也**不是**把管理密钥置零。它仅控制“非接触敏感命令是否强制要求底层 APDU 传输加密”。
> - **配置 SM 后的自动保护机制**：即使安装时采用了 `--params 00`，一旦管理员在卡内配置了 SM 静态密钥，Applet 的接口策略检查（`SmartPGPApplet.java:164`）会自动要求后续的所有 NFC 敏感操作必须使用 SM 安全信道。

#### 一键脚本安装：
```cmd
install.bat --reader PCD
```
*(PowerShell 用户可执行 `./install.ps1 --reader PCD`)*

脚本默认使用 NFC 兼容模式（`--params 00`）。若需启用严格模式，可附加 `--strict-contactless`。若目标卡上已存在旧版实例，需显式传入 `--replace-smartpgp` 以确认覆盖安装。

---

### ⚙️ 6. 源码构建说明与可复现构建

**前置依赖**：锁文件指定的 JDK 11.0.32.1+1 与 Python 3.10+。

```cmd
build.bat
```
*(PowerShell 用户可执行 `./build.ps1`)*。

构建系统采用确定性可复现管道：使用锁定的工具链在独立环境中执行双重编译、规范化 ZIP 时间戳与元数据，并通过 Oracle 离线 Verifier 字节码校验。构建出的 CAP 文件在任何机器上均可逐字节完全复现。

构建产物输出于：`dist/SmartPGPApplet.cap`（完整哈希记录于 `dist/SHA256SUMS`）。

用户可运行以下命令验证公开发行版与源码提交的一致性：
```powershell
python tools/verify_release.py
```
详细构建规范请参见 [REPRODUCIBLE-BUILD.md](REPRODUCIBLE-BUILD.md)。

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
