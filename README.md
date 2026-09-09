# ZJU-Course

一个在你自己电脑上运行的**学在浙大**（`courses.zju.edu.cn`）轻量客户端，用浙大统一身份认证登录，纯本地、纯 Python 标准库、无第三方依赖。

> ⚠️ 非官方第三方客户端，仅供个人学习自用，请遵守学校相关规定。

## 功能

- 课程 / 作业管理：按学期与状态分组、提交记录多版本、多文件批量交作业
- 课件章节：按章组织、在线预览（图片 / PDF / Office / TXT 等）
- **课堂录播**：课程详情列出每节录播，可看回放，并调智云课堂官方接口导出 PPT
- **成绩查询**：从教务系统 ETA 拉取成绩，算加权 GPA 与学分
- 文件流式下载，自动按课程分文件夹

## 快速开始

网页模式（推荐，零依赖）：

```bash
python server.py
```

浏览器会自动打开 `http://127.0.0.1:8733/`，用学号 + 统一认证密码登录即可。Windows 也可直接双击 `run_server.bat`。

桌面 exe（仅 Windows）：装好 `pyinstaller`/`pywebview`/`pillow` 后双击 `make_exe.bat`，产物在 `dist\ZJU-Course.exe`。

## 命令行

| 参数 | 作用 |
|---|---|
| `--no-browser` | 启动后不自动打开浏览器 |
| `--port 8733` | 固定监听端口（冲突即报错） |
| `--tauri` | 打印端口供外部外壳读取 |

## 目录

```
server.py          后端（HTTP 服务 + 浙大接口代理 + 会话），纯标准库
index.html         前端单页
desktop.py         桌面外壳（打包 exe 用）
make_exe.bat / run_server.bat   打包 / 启动脚本（Windows）
ZC.jpg / ZC.ico    应用图标
tools/             PyInstaller 解包工具
```

## 安全

- 登录会话（Cookie + 学号）用 Windows DPAPI 加密存本地，换机 / 换账户无法解密。
- 密码只在登录瞬间存在于内存，绝不落盘。
- `session.dat` 等本地数据已被 `.gitignore` 排除，不会上传。

## License

[MIT](LICENSE)
