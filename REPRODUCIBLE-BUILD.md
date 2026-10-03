# Reproducible SmartPGP CAP / 可复现构建

## Scope / 范围

The release requirement is **identical bytes**, not only equivalent Java Card components. `dist/SmartPGPApplet.cap`, `prebuilt/SmartPGPApplet.cap` and any deployment copy must have the same SHA-256. The public single-applet installer checks provenance before loading. Card production tooling is separate and is not part of this repository.

本机制覆盖 `src/` 中SmartPGP applet源码到发行CAP的重建，使用固定版本的工具及依赖。它不表示整张卡、JCOP原生OS、Oracle SDK或25519包装库全部开源。

**Dependency boundary:** `lib/Curve25519.cap` is an unchanged, pinned upstream binary. Upstream states that the full implementation source is not provided; the Java classes in `curve25519.jar` are compilation stubs/interfaces. Publishing or hashing that binary does not turn it into a source-reproducible implementation. The exact binary hash is part of `tools/toolchain-lock.json` and the release manifest. The NXP native implementation is outside this applet build as well.

上游说明：`https://github.com/suut/Curve25519-JavaCard`，README的Security部分。本项目不能据此宣称“整个运行栈100%开源”；若要求所有应用依赖都可从源码重建，需要取得或替换该包装库的完整实现并重新审计。这里不会悄悄换掉已测的密码实现来掩盖缺口。

## Why older hashes differed / 旧哈希为什么不同

Oracle converter writes the build wall clock into ZIP timestamps and `Java-Card-CAP-Creation-Time` in `META-INF/MANIFEST.MF`. Earlier builds on the same day could therefore have different whole-file hashes despite identical CAP components and `.class` payloads. That is unsuitable as a release identity.

当前构建将容器变动固定为：

- ZIP条目名称排序；ZIP_STORED，不依赖压缩库版本。
- 所有ZIP时间固定为 `2000-01-01 00:00:00`，移除额外字段/注释，固定归档属性。
- 只把MANIFEST中的 `Java-Card-CAP-Creation-Time` 固定为对应UTC时间。它是**可复现占位时间**，不是实际构建日期。
- 所有 `.cap` 二进制组件、附带class/XML及其它payload原样保留；工具逐项验证未修改。
- 对最终规范化CAP再次执行Oracle off-card verifier。

不把源码提交号嵌入CAP的易变元数据；源码身份在发行清单中绑定，避免提交哈希的自引用问题。

## Toolchain / 固定工具链

The reference build uses Windows x86_64, Eclipse Adoptium Temurin JDK **11.0.32.1+1**, Python **3.10 or later**, Oracle converter/verifier **3.1.0** targeting Java Card **3.0.5**. The exact JDK release, Java/javac/JVM/modules bytes and every tool JAR/API/wrapper input are pinned in `tools/toolchain-lock.json`.

JDK必须从可信供应商获取并匹配锁文件。构建器不自动下载工具或依赖。指定完整JDK路径；仅安装JRE不够。当前字节一致性承诺针对这套已验证的工具链，不把未经验证的其它JDK/平台称为可互换。

## Rebuild a published release / 用户复验

```powershell
# Clone/check out the publicly supplied release (includes Git history).
# Use the JDK specified in tools/toolchain-lock.json.
python tools/verify_release.py
python tools/build_verified.py --jdk "C:/path/to/jdk-11.0.32.1+1" --check-release
```

`verify_release.py` checks the complete CAP hash, dist/prebuilt equality, checksum file, canonical ZIP, all inputs, and their presence with matching contents in the recorded source commit. This alone is integrity/provenance checking, not recompilation. `--check-release` really recompiles in **two fresh directories**, converts and independently verifies both, compares their full bytes, then compares them against the published CAP. It never overwrites the published files.

完整发行哈希见 `dist/SHA256SUMS`。构建清单 `dist/build-manifest.json` 包含完整 `source_commit`、每个Java源文件/构建脚本/依赖/JDK文件哈希，以及CAP整体和内部条目哈希。文本输入仅规范化CRLF为LF，二进制输入和CAP按完整原始字节哈希。

`--without-git`只适用于没有Git历史的源码ZIP，它不能验证提交归属，属于更弱的文件校验。正式重建建议克隆公开仓库并使用默认Git校验。

## Maintainer release sequence / 维护者发行顺序

1. Commit the Java source, build scripts, toolchain lock and dependency changes. Uncommitted/untracked Java input is rejected by release builds. Do not change inputs during a build.
2. Run `python tools/build_verified.py --jdk "..."`. Both independent builds and final CAP verifications must succeed before files are published.
3. Review and commit `dist/SmartPGPApplet.cap`, `prebuilt/SmartPGPApplet.cap`, `dist/build-manifest.json`, `dist/SHA256SUMS` in a separate artifact commit. The manifest references the preceding **source/build-input commit**, not itself.
4. Rebuild from a separate clone/checkout with `--check-release`. Distribute only the committed artifact bytes. Authenticate the published release/commit through your distribution process; a hash stored beside a file is not a digital signature.
5. Deployment copies must be copied from that exact committed release, with the public manifest unchanged. Reject mismatches instead of regenerating local hashes to accept another CAP.

`--check-release` at the artifact commit is supported: it validates that its build inputs still match the recorded source commit. Documentation or unrelated tests may evolve without changing the applet payload; source/build-input changes require a new release build.

## What this does not prove / 不代表什么

- GP registry AID/version does not prove which bytes are currently installed. A normal applet installation does not expose the original ZIP as a readable file. Keep trustworthy loading records tying serial/profile to the public release hash; this is traceability, not hardware attestation.
- Old cards loaded from pre-canonical ZIPs are not retrospectively claimed to have been loaded from the new file. If CAP component payloads match, record that fact separately. Reinstallation deletes applet keys/data and is never silently performed just to change a host ZIP hash.
- Installation parameters and personalization affect behavior even when CAP bytes match. Record NFC profile (`00`/`01`), instance AID and key/PIN setup separately from the CAP identity.
- Canonical ZIP generation and reproducible Java Card builds do not certify side-channel resistance or turn binary-only dependencies into open-source components.
