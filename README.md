# Trojan-R

高性能的 Trojan 代理，使用 Rust 实现。为嵌入式设备或低性能机器设计。R 意为 **R**ust / **R**apid。

**Trojan-R 目前为实验性项目，仍处于重度开发中，协议、接口和配置文件格式均可能改变，请勿用于任何生产环境。**

## 特性

- 极致性能

    牺牲部分灵活性，采用激进的性能优化策略以极力减少不必要的开销。采用[更高效](https://jbp.io/2019/07/01/rustls-vs-openssl-performance.html)的 `rustls` （相较 openssl）建立 TLS 隧道以提升加解密的性能表现。

    使用 tokio 异步运行时，允许 `Trojan-R` 同时使用所有 CPU 核心，保证低时延和高效的吞吐能力。

    > 需要更多 benchmark 数据和更多优化

- 低内存占用

    Rust 无 GC 机制，内存占用可被预计。简化的握手和连接流程，仅使用极少的堆内存和复制。

    > 需要更多 benchmark 数据和更多优化

- 简易配置

    使用 toml 格式配置，仅需数行配置即可启动完整客户端或服务器。

- 内存安全

    使用 Rust 语言实现，可证明的内存安全性。在语法层面保证所有内存操作安全可靠。无竞争条件，无悬挂指针，无 UAF，无 Double Free。

- 密码学安全

    使用 `rustls` 建立 TLS 加密安全信道，过时的或不安全的密码学套件[均被禁用](https://docs.rs/rustls/0.18.1/rustls/#non-features)。`Trojan-R` 强制开启服务器证书校验以防止中间人攻击。

- 隐蔽传输

    `Trojan-R` 使用 TLS 建立代理隧道，难以从正常 TLS 流量中被区分。支持协议回落，在遭到主动探测时将与普通 TLS 服务器表现一致。

- 跨平台支持

    `Trojan-R` 可被交叉编译，支持 Android， Linux，Windows 和 MacOS 等操作系统，以及 x86，x86_64，armv7，aarch64 等硬件平台。

## 非特性

由于与项目的设计原则冲突，下列特性不计划实现

- 统计功能，包括 API 和数据库对接等

- 路由功能

- 用户自定义协议栈

- 透明代理

如果需要实现上述功能，请使用其他类似工具与 `Trojan-R` 组合实现。

## 设计原则

- 安全性

    `Trojan-R` 不涉及底层操作，且目前的性能瓶颈与其无关，无使用 unsafe rust 的必要。协议回落和 TLS 配置等安全敏感代码经过仔细考虑和审计，同时也欢迎更多来自开源社区的安全审计。

    目前 `Trojan-R` 使用 `#![forbid(unsafe_code)]` 禁用 unsafe rust。如未来有必要使用 unsafe rust 时，必须经过严格审计和测试。

- 使用静态分发而非动态分发

    协议实现使用统一的 trait。协议嵌套使用静态分发，以保证嵌套协议栈的函数调用关系在编译时被确定，使编译器可以进行内联和更好的优化。

- 低内存分配

    减少热点代码的内存分配，用引用替换复制，以实现更高的性能和更低的内存开销。

- 简洁

    保持最简洁干净的实现，以保证最低的代码复杂度，尽可能少的性能开销，并增加可靠性和减少攻击面。

## 部署和使用

`Trojan-R` 使用 toml 进行配置，参考 `config` 文件夹下配置文件。

## 编译

```shell
cargo build --release
```

交叉编译基于 `cross` 完成，编译前请确认已经安装 `cross` (`cargo install cross`)

```shell
make armv7-unknown-linux-musleabihf
```

编译默认开启链接时优化，以提升性能并减小可执行文件体积，因此编译耗时可能较其他项目更长。

编译完成后可以使用 `strip` 去除调试符号表以减少文件体积。

## TODOs

- [ ] 更完善的交互接口和文档

- [ ] 更多的单元测试和集成测试

- [ ] 性能调优

- [ ] 可复现的 benchmark 环境

- [ ] 实现 lib.rs 和导出函数

- [x] 分离客户端和服务端 features

- [ ] Github Actions

## 致谢

- [trojan](https://github.com/trojan-gfw/trojan)

- [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
