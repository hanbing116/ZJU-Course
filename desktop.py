# -*- coding: utf-8 -*-
"""
ZJU-Course 桌面外壳：起本地服务（后台线程）+ pywebview 原生窗口。
打包：pyinstaller --onefile --windowed --icon ZC.ico --add-data index.html
"""
import ctypes
import json
import os
import threading

import server as srv

GEOM_FILE = os.path.join(srv.DATA_DIR, 'window.json')


class Api:
    """暴露给网页 JS 的原生能力（pywebview js_api）。"""

    def choose_folder(self):
        """弹系统原生「选择文件夹」对话框，返回所选路径（取消返回空串）。"""
        import webview
        try:
            result = webview.windows[0].create_file_dialog(
                webview.FOLDER_DIALOG)
            if result:
                # FOLDER_DIALOG 返回 tuple/list，取第一项
                return result[0] if isinstance(result, (list, tuple)) else result
        except Exception:
            pass
        return ''


def default_size():
    """按屏幕大小取首次默认尺寸：约屏宽 65%、屏高 78%（封顶 1280x860）。"""
    try:
        user32 = ctypes.windll.user32
        try:
            user32.SetProcessDPIAware()
        except Exception:
            pass
        sw, sh = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
        w = max(900, min(1280, int(sw * 0.65)))
        h = max(620, min(860, int(sh * 0.78)))
        return w, h
    except Exception:
        return 1240, 850


def load_geometry():
    """读上次关闭时的窗口大小/位置；没有或异常就用默认尺寸（系统居中）。"""
    try:
        with open(GEOM_FILE, 'r', encoding='utf-8') as f:
            g = json.load(f)
        w = int(g.get('w') or 0)
        h = int(g.get('h') or 0)
        x, y = g.get('x'), g.get('y')
        kw = {}
        if w >= 400 and h >= 300:
            kw['width'], kw['height'] = w, h
        if isinstance(x, int) and isinstance(y, int):
            kw['x'], kw['y'] = x, y
        return kw
    except Exception:
        return {}


def main():
    # 选端口：优先 8733，被占就换随机（他人的电脑上更不容易撞）
    port = srv.pick_port(srv.PREFERRED_PORT, allow_random=True)
    url = f'http://{srv.HOST}:{port}/'

    httpd = srv.ThreadingHTTPServer((srv.HOST, port), srv.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    import webview

    geom = load_geometry()
    if 'width' not in geom:
        w, h = default_size()
        geom['width'], geom['height'] = w, h
    win = webview.create_window(
        'ZJU-Course',
        url,
        min_size=(860, 600),
        background_color='#f5f7fa',
        js_api=Api(),
        **geom,
    )

    def save_geometry():
        """窗口关闭时记住大小/位置，下次打开原样恢复。"""
        try:
            data = {'w': int(win.width), 'h': int(win.height)}
            x, y = win.x, win.y
            if isinstance(x, int) and isinstance(y, int):
                data['x'], data['y'] = x, y
            with open(GEOM_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f)
        except Exception:
            pass

    win.events.closed += save_geometry

    try:
        webview.start()
    finally:
        try:
            httpd.shutdown()
        except Exception:
            pass
        srv.SESSION.close()


if __name__ == '__main__':
    main()
