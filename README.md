# ZJU-Course

一个可以在 Windows 上运行的**学在浙大**轻量客户端，用浙大统一身份认证登录，纯本地、纯 Python 标准库、无第三方依赖。

## 功能

- **课程 / 作业管理**：按学期与状态分组、提交记录多版本、多文件批量交作业
- **课件章节**：按章组织、在线预览（图片 / PDF / Office / TXT 等）
- **课堂录播**：课程详情列出每节录播，可看回放，并调智云课堂官方接口导出 PPT
- **成绩查询**：从 ETA 系统拉取成绩，算加权 GPA 与学分
- 文件流式下载，自动按课程分文件夹

## 获取

release中已打包好 exe 文件 `ZJU-Course.exe`，下载后解压放置桌面可直接使用。

下载：https://github.com/hanbing116/ZJU-Course/releases/download/ZJU_course/ZC.zip

## 安全

- 登录会话（Cookie + 学号）用 Windows DPAPI 加密存本地，换机 / 换账户无法解密。
- 密码只在登录瞬间存在于内存，绝不落盘。

## License

[MIT](LICENSE)
