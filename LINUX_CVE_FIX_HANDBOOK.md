# Linux 致命漏洞修复手册

> 来源声明（红线 4：不伪造来源）：
> - CVE 描述 / CVSS / CWE / 受影响版本：逐字引自本工作区 `vuln-hunter/nvd_cache/*.json`（NVD 原始描述）。
> - CVE-2024-6387 修复版本（OpenSSH 9.8p1）：依据 NVD 引用列表中的 OpenSSH 官方 release notes（`openssh.com/txt/release-9.8`）与 Arch Linux 公告（`the-sshd-service-needs-to-be-restarted-after-upgrading-to-openssh-98p1`）。
> - 修复命令：通用运维实践（Ubuntu/Debian 与 RHEL/CentOS 各给一套），**具体包版本号以你所用发行版的官方安全公告为准**，本手册不编造发行版特定版本号。
> - 所有操作需人工确认后执行；升级内核 / OpenSSH 前先在测试环境验证。

## 速查表

| CVE | 组件 | CVSS | 攻击面 | 修复动作 |
|---|---|---|---|---|
| CVE-2024-6387 | OpenSSH `sshd` | 8.1 | **远程未认证** RCE | 升级 OpenSSH ≥ 9.8p1 |
| CVE-2023-1281 | Linux 内核 tcindex | 7.8 | 本地提权 | 升级内核（含修复 commit） |
| CVE-2021-27365 | Linux 内核 iSCSI | 7.8 | 本地（Netlink） | 升级内核（> 5.11.3） |
| CVE-2021-23134 | Linux 内核 NFC | 7.8 | 本地提权 | 升级内核（≥ 5.12.4） |
| CVE-2021-20322 | Linux 内核 ICMP/UDP | 7.4 | 远程 | 升级内核 |
| CVE-2021-27364 | Linux 内核 iSCSI | 7.1 | 本地（Netlink） | 升级内核（> 5.11.3） |
| CVE-2021-23133 | Linux 内核 SCTP | 6.7 | 本地提权 | 升级内核 |
| CVE-2022-3566 | Linux 内核 TCP | 4.6 | 本地 | 升级至 4.19.317 / 5.4.279 / 5.10.221 / 5.15.162 / 6.1 |
| ⚠ CVE-2023-27997 | FortiOS / FortiProxy SSL-VPN（非内核） | 9.8 | **远程 RCE，在野利用** | 升级 FortiOS / FortiProxy（见 Fortinet 公告） |

> 修复优先级（人工判断依据，非自动结论）：CVE-2024-6387 与 CVE-2023-27997 可远程触发且存在公开利用 → 优先；其余为本地提权类 → 次之。

---

## 1. CVE-2024-6387 — OpenSSH sshd（regreSSHion，最高优先）

**原文描述**（nvd_cache，逐字）：*"A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period."*

- CVSS 3.1：8.1（AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H）；CWE-364；NVD 引用含 exploit 列表 → 公开利用存在
- **修复版本：OpenSSH ≥ 9.8p1**

### 检查是否受影响

```bash
sshd -V 2>&1 | head -1        # 查看 sshd 版本（低于 9.8p1 即受影响）
```

### 修复（升级 OpenSSH）

Ubuntu / Debian：

```bash
sudo apt update
sudo apt install --only-upgrade openssh-server openssh-client
sudo systemctl restart ssh
sshd -V 2>&1 | head -1        # 验证 ≥ 9.8p1
```

RHEL / CentOS / Rocky / Alma：

```bash
sudo yum update openssh-server openssh-clients
sudo systemctl restart sshd
sshd -V 2>&1 | head -1        # 验证 ≥ 9.8p1
```

> 注意：若发行版仓库暂未推送修复包，请按官方公告操作（Debian: security-tracker.debian.org/tracker/CVE-2024-6387；Ubuntu: USN-6859-1；Red Hat: RHSA-2024:4312 等）。

### 临时缓解（在升级完成前，待验证项）

- 网络层限制：防火墙只放行可信来源访问 22 端口，缩小暴露面（通用实践，无版本依赖）。
- `sshd_config` 相关参数（如 LoginGraceTime、MaxStartups）的调节需以 OpenSSH / 厂商官方公告建议为准，**本手册不逐字转述**，避免引入错误；请参考 qualys 公告（qualys.com/2024/07/01/cve-2024-6387/regresshion.txt）。

---

## 2. CVE-2023-1281 — Linux 内核 tcindex 提权

**原文描述**（逐字）：*"Use After Free vulnerability in Linux kernel traffic control index filter (tcindex) allows Privilege Escalation. The imperfect hash area can be updated while packets are traversing, which will cause a use-after-free when 'tcf_exts_exec()' is called with the destroyed tcf_ext. A local attacker user can use this vulnerability to elevate its privileges to root. This issue affects Linux Kernel: from 4.14 before git commit ee059170b1f7e94e55fa6cadee544e176a6e59c2."*

- CVSS 7.8；CWE-416；本地提权

### 检查与修复

```bash
uname -r                      # 记录当前内核版本
# 修复：升级到含 commit ee059170b1f7e94e55fa6cadee544e176a6e59c2 的内核
sudo apt update && sudo apt install --only-upgrade linux-image-$(uname -r | cut -d- -f1)   # Ubuntu/Debian 示例
# 或
sudo yum update kernel        # RHEL 系示例
sudo reboot
uname -r                      # 重启后验证
```

---

## 3. CVE-2021-27365 — Linux 内核 iSCSI（Netlink 越界）

**原文描述**（逐字）：*"An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a Netlink message."*

- CVSS 7.8；CWE-787（越界写）；本地触发

**修复**：升级内核至 5.11.3 之后的修复版本（命令同上节内核升级模板）。

---

## 4. CVE-2021-23134 — Linux 内核 NFC 套接字 UAF

**原文描述**（逐字）：*"Use After Free vulnerability in nfc sockets in the Linux Kernel before 5.12.4 allows local attackers to elevate their privileges. In typical configurations, the issue can only be triggered by a privileged local user with the CAP_NET_RAW capability."*

- CVSS 7.8；CWE-416；本地提权（需 CAP_NET_RAW，典型配置下受限）

**修复**：升级内核至 ≥ 5.12.4。

---

## 5. CVE-2021-20322 — Linux 内核 UDP 源端口随机化绕过

**原文描述**（逐字）：*"A flaw in the processing of received ICMP errors (ICMP fragment needed and ICMP redirect) in the Linux kernel functionality was found to allow the ability to quickly scan open UDP ports. This flaw allows an off-path remote user to effectively bypass the source port UDP randomization. The highest threat from this vulnerability is to confidentiality and possibly integrity, because software that relies on UDP source port randomization are indirectly affected as well."*

- CVSS 7.4；CWE-330；远程（off-path）

**修复**：升级内核到含修复的版本。

---

## 6. CVE-2021-27364 — Linux 内核 iSCSI（Netlink 越界读）

**原文描述**（逐字）：*"An issue was discovered in the Linux kernel through 5.11.3. drivers/scsi/scsi_transport_iscsi.c is adversely affected by the ability of an unprivileged user to craft Netlink messages."*

- CVSS 7.1；CWE-125（越界读）；本地

**修复**：升级内核至 5.11.3 之后的修复版本。

---

## 7. CVE-2021-23133 — Linux 内核 SCTP 套接字竞态

**原文描述**（逐字）：*"A race condition in Linux kernel SCTP sockets (net/sctp/socket.c) before 5.12-rc8 can lead to kernel privilege escalation from the context of a network service or an unprivileged process. If sctp_destroy_sock is called without sock_net(sk)->sctp.addr_wq_lock then an element is removed from the auto_asconf_splist list without any proper locking. This can be exploited by an attacker with network service privileges to escalate to root or from the context of an unprivileged user directly if a BPF_CGROUP_INET_SOCK_CREATE is attached which denies creation of some SCTP socket."*

- CVSS 6.7；CWE-362；本地/网络服务提权

**修复**：升级内核（修复在 5.12-rc8 之后的版本）。

---

## 8. CVE-2022-3566 — Linux 内核 TCP getsockopt/setsockopt 竞态

**原文描述**（逐字）：*"A vulnerability was identified in Linux Kernel up to 4.19.316/5.4.278/5.10.220/5.15.161. This impacts the function tcp_getsockopt/tcp_setsockopt of the component TCP Handler. Such manipulation leads to race condition. A high complexity level is associated with this attack. The exploitability is said to be difficult. … Upgrading to version 4.19.317, 5.4.279, 5.10.221, 5.15.162 and 6.1 will fix this issue."*

- CVSS 4.6；CWE-362；利用难度高

**修复**（原文给出明确修复版本）：升级至 **4.19.317 / 5.4.279 / 5.10.221 / 5.15.162 / 6.1** 或更高。

---

## 9. ⚠ CVE-2023-27997 — FortiOS / FortiProxy SSL-VPN（非 Linux 内核）

**原文描述**（逐字）：*"A heap-based buffer overflow vulnerability [CWE-122] in FortiOS version 7.2.4 and below, version 7.0.11 and below, version 6.4.12 and below, version 6.0.16 and below and FortiProxy version 7.2.3 and below, version 7.0.9 and below, version 2.0.12 and below, version 1.2 all versions, version 1.1 all versions SSL-VPN may allow a remote attacker to execute arbitrary code or commands via specifically crafted requests."*

- CVSS 9.8；CWE-122；**远程 RCE，public_exploit=yes（在野利用）**
- 此漏洞属于 Fortinet 设备固件（虽运行于类 Unix 环境，但不是 Linux 内核漏洞），单独列出。

**修复**：升级 FortiOS / FortiProxy 至官方公告中的修复版本（以 Fortinet PSIRT 公告为准，本手册不编造具体固件版本号）。无法立即升级时：限制 SSL-VPN 管理面暴露 + 监控异常登录（临时缓解，人工确认）。

---

## 通用验证步骤（升级后）

```bash
uname -r                      # 内核版本
sshd -V 2>&1 | head -1        # OpenSSH 版本
cat /proc/version             # 内核构建信息
# 确认系统已无待重启标记（Debian/Ubuntu）：
ls /var/run/reboot-required 2>/dev/null && echo "需重启" || echo "无重启标记"
```

## 通用提醒

1. **先备份、先测试**：生产环境升级前在测试机复现。
2. **重启窗口**：内核升级必须重启生效；OpenSSH 升级后需重启 ssh/sshd 服务（Arch 官方新闻亦特别提醒此点）。
3. **决策人工**：本手册只提供材料与步骤，升级窗口、回滚策略、是否停机由运维与业务方决定。
