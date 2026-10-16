# ESP32-S3 校园网共享路由（深澜 SRun 自动认证 + NAPT）

把 ESP32-S3 变成一个小型无线软路由：连上学校的开放 WiFi，自动完成深澜 SRun 门户认证，
再开热点并用 NAPT 把网络转发给连上来的手机/电脑，实现**免认证上网**。

## 功能

- **自动认证**：完整实现深澜 `srun_bx1`（`{SRBX1}`）认证协议，无需人工登录
- **NAPT 转发**：`esp_netif_napt_enable()` 开启 IP 地址/端口转换，下游设备共享出口
- **自动重连**：STA 掉线后带节流重试，附断开原因中文化诊断
- **开机自检**：启动即扫描周边 AP，确认目标 SSID 可见
- **信道自适应**：等 STA 连上后再按实际信道启动热点，保证 AP/STA 同信道共存

## 硬件要求

- **ESP32-S3 Dev Module**（推荐带 PSRAM 的 N16R8/N8R8）
- 2.4GHz WiFi 环境（ESP32-S3 不支持 5GHz）

## 环境要求

- **Arduino ESP32 Core ≥ 3.0.0**（必须，NAPT 依赖 `esp_netif_napt_enable()`）
- 该 API 自 core 3.0.0 / IDF 5.x 起才提供。core 2.0.x 的预编译 `liblwip.a`
  中 `CONFIG_LWIP_IP_FORWARD` / `CONFIG_LWIP_IPV4_NAPT` 均未开启，无法使用。

## 快速开始

### 1. 修改配置

打开 `wendu.ino`，按步骤填写顶部的用户配置区（**全部需要自行填写**）：

```c
/* 【步骤 1】学校 2.4G WiFi
 *   ESP32-S3 只支持 2.4GHz，不支持 5GHz。
 *   有密码就填密码；开放网络（无密码）留空字符串 ""。 */
#define CAMPUS_SSID   "校园网WiFi名称"
#define CAMPUS_PASS   ""                /* 开放网络则填 "" */

/* 【步骤 2】Portal 认证地址
 *   浏览器访问该地址应能弹出校园网登录页。 */
#define PORTAL        "http://校园网IP地址"

/* 【步骤 3】认证账号（注意：不是 WiFi 密码） */
#define USERNAME      "学号"
#define PASSWORD      "校园网密码"
#define AC_ID         "认证点编号"         /* 通常填 "1"，见登录页 URL */

/* 【步骤 4】自建热点（手机连这个上网） */
#define AP_SSID       "你的热点名称"
#define AP_PASS       "你的热点密码"       /* WPA2 要求至少 8 位 */
```

#### 怎么找到这些值

| 配置项 | 获取方法 |
|---|---|
| `CAMPUS_SSID` | 手机 WiFi 列表里，**不带 `-5G` 后缀**的那个名字 |
| `CAMPUS_PASS` | 该 WiFi 的密码；显示"开放/无密码"就填 `""` |
| `PORTAL` | 浏览器访问该地址能弹出登录页即可；不确定可断网后看浏览器跳转地址 |
| `AC_ID` | 登录页 URL 里 `ac_id=` 后面的值，通常是 `1` |
| `USERNAME` / `PASSWORD` | 校园网账号密码 |

烧录后若串口显示 `[SCAN] 目标 SSID 不在列表`，说明 `CAMPUS_SSID` 填错了或该 WiFi 是 5GHz。

### 2. 编译烧录

Arduino IDE 直接打开 `wendu.ino`；或用命令行：

```powershell
arduino-cli compile --fqbn esp32:esp32:esp32s3 .
arduino-cli upload  --fqbn esp32:esp32:esp32s3 -p COM12 .
```

> 国内网络安装 core 3.x 时，若 GitHub 下载超时，可在 `arduino-cli.yaml` 里
> 设置 `network.proxy: http://127.0.0.1:<代理端口>`。

### 3. 使用

手机/电脑连上热点 `ESP32-Router`（密码见配置）即可上网，无需再登录校园网。

## 认证协议实现要点

协议细节来自学校 Portal 前端源码（`Portal.js`），非公开文档，实现要点：

| 环节 | 算法 |
|---|---|
| 密码摘要 | `HMAC-MD5(key=challenge, msg=password)`，结果前缀 `{MD5}` |
| `info` 字段 | **XXTEA** 加密 JSON，再用**深澜自定义 base64 字母表**编码，前缀 `{SRBX1}` |
| `chksum` | **SHA1**，拼接顺序 `token+user+token+hmd5+token+acid+token+ip+token+n+token+type+token+info` |

**自定义 base64 字母表**（不是标准字母表，极易踩坑）：

```
LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA
```

### 已踩过的坑

1. **`info` 必须做 URL 编码** —— 自定义 base64 含 `+` `/` `=`，POST 表单里 `+` 会被
   解析成空格，导致服务端解密失败返回 `sign_error`。用 `urlEnc()` 处理。
2. **`info` 里的 `password` 是明文** —— 不是摘要值。只有 POST 的 `password` 字段才带 `{MD5}`。
3. **不要手动下发 AP 的 DNS** —— softAP 默认由框架自建 DNS 转发，强行指定外部 DNS
   会让客户端绕过转发直连公网，查询超时导致下行从 8Mbps 掉到 <1Mbps。
4. **不要做周期性 `scanNetworks()`** —— 扫描会占满射频 2~3 秒，AP+STA 单射频本就抢信道，
   频繁扫描会显著拖垮吞吐。仅在开机时扫描一次用于诊断。
5. **不要强制 `esp_wifi_set_max_tx_power()`** —— 会破坏芯片自动射频校准，
   实测信号从 -68dBm 劣化到 -81dBm。

## 性能参考

| 场景 | 吞吐 |
|---|---|
| 校园网直连（电脑测速） | ~104 Mbps |
| 经 ESP32 转发 | **~8 Mbps** |

8Mbps 接近 ESP32-S3 做 softAP 转发的实际上限，受限于：2.4GHz HT20 单流物理层、
单射频 AP/STA 时分复用、lwIP 软件 NAPT。参考 espressif/arduino-esp32
[issue #6706](https://github.com/espressif/arduino-esp32/issues/6706)，
该软 AP 转发吞吐问题为框架层已知缺陷。

## 文件结构

```
wendu/                 # Arduino sketch（库结构，目录名需与 .ino 同名）
├── wendu.ino          # 主程序
├── README.md
└── .gitignore
```

> 仓库中不含任何真实凭据，所有敏感字段均为占位符。使用前请按上方
> “快速开始 → 修改配置”填写你自己的信息。

## 免责声明

本项目用于学习研究 ESP32 的 softAP + NAPT 与深澜认证协议实现。
请遵守所在网络的管理规定，仅在获得授权的网络中使用。
