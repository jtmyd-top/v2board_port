
# v2board_port

该脚本用于自动修改 V2Board 节点的端口。通过使用此脚本，用户可以轻松更新机场节点的端口设置。请确保在运行此脚本之前，您已经配置好相应的环境和依赖项。

## 功能

- 自动获取 V2Board 节点信息
- 随机生成新的端口并更新指定节点的端口
- 支持多个节点的批量修改
- 提供简单的登录功能，使用者可在后台管理自己的节点

## 使用方法

1. **设置基本参数**：在代码中定义 `BASE_URL`, `EMAIL`, 和 `PASSWORD`，并根据需要修改 `admin_url`。
2. **依赖安装**: 确保 Python 环境中安装了 `requests` 库。可通过以下命令安装：
   ```bash
   pip install requests
   ```
3. **定时任务**：根据您的需求自行设置定时任务，以定期运行该脚本。例如，可以使用 `cron` 在 Linux 系统中设置定时任务以及青龙面板。
4. **运行脚本**：
   ```bash
   python v2board_port.py
   ```

## 免责声明

**本脚本的使用需遵循以下条款：**

- 本脚本的用户应自行负责其使用行为，涉及的任何法律后果由用户自行承担。
- 用户应确保所执行的操作符合相关法律法规的要求。
- 本脚本不对用户因使用或无法使用本脚本而产生的任何直接、间接、偶然、特殊及后续损害承担责任。
- 使用本脚本即表示用户已充分理解并同意遵守上述条款。


## 注意事项

- 请谨慎使用此脚本，确保您的 V2Board 环境已经备份以防不测。
- 修改节点端口可能会影响与之相关的服务，请确认了解每个节点的设置。

---

感谢您使用 v2board_port！希望本脚本能为您的 V2Board 节点管理带来便利。

