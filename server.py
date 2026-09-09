"""
zjucourse —— 学在浙大 (courses.zju.edu.cn) 第三方本地客户端 · 后端 v2
=====================================================================
纯 Python 标准库实现，无需 pip install 任何东西。

【它能做什么】
  1) 用浙大学号 + 密码，在本机完成「浙大 CAS」登录，并保存会话；
  2) 代理学在浙大的接口（学期 / 课程 / 作业 / 提交），顺带解决浏览器跨域；
  3) 提供一个本地网页服务（只监听 127.0.0.1，外网访问不到）。

【安全设计】（这是 v2 的重点）
  · 密码：只在登录那一刻存在内存里，用于加密后 POST，**绝不写入任何文件**；
  · 会话 Cookie：用 Windows 的 DPAPI 加密后落盘，密钥绑定「当前 Windows 用户账户」，
     换个账户或拷到别人电脑上，文件就是一堆乱码，解密不出来；
  · 本机接口鉴权：每次启动随机生成一个 token，只有本机同源页面拿得到，
     同一个局域网/本机的其它程序无法偷偷调用你的会话；
  · 服务器校验：所有 api 请求都会检查 Host 头，防止 DNS rebinding 之类的攻击；
  · 不写日志：服务端不记录你的任何操作，也不上传任何数据到任何地方。

【性能设计】
  · HTTPS 连接池：复用 TCP + TLS 握手（省掉每次上百毫秒的握手开销）；
  · 并行拉取：各门课的作业同时请求，而不是一门一门排队；
  · 短缓存：课程列表 30 秒内复用，避免同一份数据重复请求。

【数据范围】
  · 默认拉取**全部学期**的课程和作业（不只是本学期），前端可按学期筛选。
"""

import base64
import datetime
import html
import http.client
import ctypes
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.cookiejar import Cookie, CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# 打包exe时资源目录是解压后的临时目录；脚本运行时用脚本所在目录
IS_FROZEN = getattr(sys, 'frozen', False)
RESOURCE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))

if IS_FROZEN:
    # exe 模式：数据放 %LOCALAPPDATA%\zjucourse
    _base = os.environ.get('LOCALAPPDATA') or os.path.expanduser('~')
    DATA_DIR = os.path.join(_base, 'zjucourse')
else:
    # 脚本模式：数据放脚本所在目录
    DATA_DIR = os.path.dirname(os.path.abspath(__file__))
os.makedirs(DATA_DIR, exist_ok=True)

HOST = '127.0.0.1'
PREFERRED_PORT = 8733
SESSION_FILE = os.path.join(DATA_DIR, 'session.dat')

# 下载文件夹配置（用户在设置里可改；存 DATA_DIR，随用户走）
DL_DIR_FILE = os.path.join(DATA_DIR, 'download_dir.json')


def _default_download_dir():
    """默认存到系统的「下载」文件夹；取不到就退回用户主目录。"""
    base = os.environ.get('USERPROFILE') or os.path.expanduser('~')
    p = os.path.join(base, 'Downloads')
    return p if os.path.isdir(p) else base


def get_download_dir():
    try:
        with open(DL_DIR_FILE, 'r', encoding='utf-8') as f:
            d = (json.load(f) or {}).get('dir') or ''
        if d and os.path.isdir(d):
            return d
    except Exception:
        pass
    return _default_download_dir()


def set_download_dir(d):
    """校验并保存自定义下载文件夹；失败返回 False（保持原设置）。"""
    d = (d or '').strip()
    if not d or not os.path.isdir(d):
        return False
    try:
        with open(DL_DIR_FILE, 'w', encoding='utf-8') as f:
            json.dump({'dir': d}, f, ensure_ascii=False)
        return True
    except Exception:
        return False

# 当前登录的学号。只用于拼 ETA 成绩查询地址（xh 参数），不存密码；
# 会随会话一起用 DPAPI 加密落盘，重启后仍可用。
CURRENT_STUID = ''


def safe_print(*args):
    """
    打包成「无控制台窗口」的 exe 后，sys.stdout 会是 None，
    这时候直接 print 会崩溃，所以统一走这里：打不出来就算了，不能影响主流程。
    """
    try:
        print(*args)
    except Exception:
        pass


HOME_URL = 'https://courses.zju.edu.cn'
PUBKEY_URL = 'https://zjuam.zju.edu.cn/cas/v2/getPubKey'
LOGIN_URL = 'https://zjuam.zju.edu.cn/cas/login'
SEMESTERS_URL = 'https://courses.zju.edu.cn/api/my-semesters'
# eta：登录成功后顺带把它的 Cookie 也种上（后台执行，成绩查询要用）
ETA_URL = 'http://eta.zju.edu.cn/index/student'

UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:88.0) Gecko/20100101 Firefox/88.0'

# 课程状态全集
COURSE_STATUS_ALL = ['ongoing', 'notStarted', 'ended']

DEFAULT_TIMEOUT = 30


class DataBlob(ctypes.Structure):
    """Windows CRYPT_INTEGER_BLOB 结构，DPAPI 用它装输入/输出的数据。"""
    _fields_ = [
        ('cbData', ctypes.c_ulong),
        ('pbData', ctypes.POINTER(ctypes.c_ubyte)),
    ]


class DPAPI:
    """
    Windows 数据保护 API 的薄封装。

    DPAPI 的好处：加密密钥由系统根据「当前用户的登录凭据」派生，我们代码里
    根本拿不到这把密钥。结果是：
      · 只有当前 Windows 用户能解密这个文件；
      · 把文件拷到别人的电脑 / 换个账户登录，解出来就是失败；
      · 我们不需要自己保管任何密码或密钥。
    """

    _crypt32 = None
    _kernel32 = None
    available = False

    @classmethod
    def _init(cls):
        if cls._crypt32 is not None:
            return cls.available
        try:
            cls._crypt32 = ctypes.windll.crypt32
            cls._kernel32 = ctypes.windll.kernel32
            cls.available = True
        except Exception:
            cls.available = False
        return cls.available

    @classmethod
    def _to_blob(cls, data: bytes):
        n = len(data)
        if n == 0:
            return DataBlob(0, None), None
        buf = ctypes.create_string_buffer(data, n)
        ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte))
        return DataBlob(n, ptr), buf  # buf 必须保活到调用结束

    @staticmethod
    def _from_blob(blob: DataBlob) -> bytes:
        if not blob.pbData or blob.cbData == 0:
            return b''
        try:
            out = ctypes.string_at(blob.pbData, blob.cbData)
        finally:
            try:
                ctypes.windll.kernel32.LocalFree(blob.pbData)
            except Exception:
                pass
        return out

    @classmethod
    def protect(cls, data: bytes) -> bytes:
        """加密（只有当前 Windows 账户能解）。失败抛异常，绝不静默降级为明文。"""
        cls._init()
        if not cls.available:
            raise RuntimeError('DPAPI 不可用')
        inp, keep = cls._to_blob(data)
        out = DataBlob(0, None)
        ok = cls._crypt32.CryptProtectData(
            ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)
        )
        del keep
        if not ok:
            raise RuntimeError('DPAPI 加密失败')
        return cls._from_blob(out)

    @classmethod
    def unprotect(cls, data: bytes) -> bytes:
        cls._init()
        if not cls.available:
            raise RuntimeError('DPAPI 不可用')
        inp, keep = cls._to_blob(data)
        out = DataBlob(0, None)
        ok = cls._crypt32.CryptUnprotectData(
            ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)
        )
        del keep
        if not ok:
            raise RuntimeError('DPAPI 解密失败（可能换了 Windows 账户）')
        return cls._from_blob(out)


def _serialise_jar(jar: CookieJar) -> bytes:
    """把 CookieJar 序列化成自定义 JSON（比 Netscape 文本格式好控制，无临时文件）。"""
    items = []
    for c in jar:
        try:
            items.append({
                'v': c.version,
                'name': c.name,
                'value': c.value,
                'port': c.port,
                'port_specified': bool(c.port_specified),
                'domain': c.domain,
                'domain_specified': bool(c.domain_specified),
                'domain_initial_dot': bool(c.domain_initial_dot),
                'path': c.path,
                'path_specified': bool(c.path_specified),
                'secure': bool(c.secure),
                'expires': c.expires,
                'discard': bool(c.discard),
                'comment': c.comment,
                'comment_url': c.comment_url,
                'rfc2109': bool(getattr(c, 'rfc2109', False)),
            })
        except Exception:
            continue
    return json.dumps(items).encode('utf-8')


def _restore_jar(data: bytes, jar: CookieJar) -> int:
    """反序列化：自己构造 Cookie 对象塞回 CookieJar。返回成功条数。"""
    count = 0
    for it in json.loads(data.decode('utf-8')):
        try:
            cookie = Cookie(
                it['v'], it['name'], it['value'],
                it['port'], it['port_specified'],
                it['domain'], it['domain_specified'], it['domain_initial_dot'],
                it['path'], it['path_specified'],
                it['secure'], it['expires'],
                it['discard'], it['comment'], it['comment_url'],
                None, it.get('rfc2109', False),
            )
            jar.set_cookie(cookie)
            count += 1
        except Exception:
            continue
    return count


def save_session():
    """把当前会话加密写入 session.dat（内含 Cookie + 学号，不含密码）。"""
    try:
        # 旧版是纯 Cookie 数组；现在升级成 {stuid, cookies}，老文件也能兼容读
        payload = {
            'stuid': CURRENT_STUID,
            'cookies': json.loads(_serialise_jar(COOKIE_JAR).decode('utf-8')),
        }
        plain = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        blob = DPAPI.protect(plain)
        tmp = SESSION_FILE + '.tmp'
        with open(tmp, 'wb') as f:
            f.write(blob)
        os.replace(tmp, SESSION_FILE)
    except Exception as e:
        safe_print(f'[提示] 会话未能加密保存：{e}（不影响本次使用）')


def load_session():
    """启动时载入上次加密保存的会话（兼容旧版纯 Cookie 数组）。"""
    global CURRENT_STUID
    if not os.path.exists(SESSION_FILE):
        return
    try:
        with open(SESSION_FILE, 'rb') as f:
            blob = f.read()
        data = json.loads(DPAPI.unprotect(blob).decode('utf-8', 'replace'))
        if isinstance(data, dict):
            CURRENT_STUID = str(data.get('stuid') or '')
            cookies = data.get('cookies') or []
        else:
            CURRENT_STUID = ''
            cookies = data or []
        _restore_jar(json.dumps(cookies, ensure_ascii=False).encode('utf-8'), COOKIE_JAR)
    except Exception:
        pass


def clear_session():
    try:
        if os.path.exists(SESSION_FILE):
            os.remove(SESSION_FILE)
            return
    except Exception:
        return


# 兼容老版本 TLS 配置（浙大某些站点证书链一般，放宽一点）
SSL_CONTEXT = ssl.create_default_context()
SSL_CONTEXT.set_ciphers('DEFAULT:@SECLEVEL=1')

COOKIE_JAR = CookieJar()
load_session()


class HttpSession:
    """
    一个很小的 HTTP 客户端：
      · 每个 host 维护若干条长连接（Keep-Alive），复用 TLS 握手；
      · 自动跟随重定向；
      · 自动收发 Cookie（交给上面的 COOKIE_JAR）；
      · 连接被服务器踢掉时，自动用新连接重试一次。
    """

    def __init__(self, jar: CookieJar, context, timeout=DEFAULT_TIMEOUT, pool_size=6):
        self._jar = jar
        self._ctx = context
        self._timeout = timeout
        self._pool_size = pool_size
        self._pool = {}      # key=(scheme, host, port) -> [conn, ...]
        self._lock = threading.Lock()

    def _acquire(self, key):
        with self._lock:
            conns = self._pool.setdefault(key, [])
            while conns:
                conn = conns.pop()
                try:
                    if conn.sock is None:
                        continue
                except Exception:
                    continue
                return conn
        scheme, host, port = key
        if scheme == 'https':
            return http.client.HTTPSConnection(host, port, context=self._ctx, timeout=self._timeout)
        return http.client.HTTPConnection(host, port, timeout=self._timeout)

    def _release(self, key, conn):
        with self._lock:
            conns = self._pool.setdefault(key, [])
            if len(conns) < self._pool_size:
                conns.append(conn)
                return
        try:
            conn.close()
        except Exception:
            pass

    def _drop(self, conn):
        try:
            conn.close()
        except Exception:
            pass

    def close(self):
        with self._lock:
            for conns in self._pool.values():
                for c in conns:
                    try:
                        c.close()
                    except Exception:
                        continue
            self._pool.clear()

    REDIRECT_CODES = (301, 302, 303, 307, 308)

    @staticmethod
    def _find_header(headers, name):
        """HTTP 头名大小写不敏感地取值。"""
        target = name.lower()
        for k, v in (headers or {}).items():
            if k.lower() == target:
                return v
        return None

    def _round_trip(self, key, method, path, req, body, timeout):
        """
        用一条连接完成一次请求/响应（失败时换新连接重试一次）。
        返回 Response 对象。
        """
        last_exc = None
        for attempt in range(2):
            conn = self._acquire(key)
            conn.timeout = timeout
            try:
                conn.putrequest(method, path)
                skip = {'host', 'accept-encoding', 'transfer-encoding',
                        'content-length', 'connection'}
                for k, v in req.header_items():
                    if k.lower() in skip:
                        continue
                    conn.putheader(k, v)
                # http.client 的 endheaders(body) 不会自动补 Content-Length，
                # 不带长度的话服务端（Werkzeug）会当请求体为空 → 400。
                # 必须在这里手动补上，否则所有带 body 的 POST/PUT 全部哑火。
                if body:
                    conn.putheader('Content-Length', str(len(body)))
                conn.endheaders(body)

                resp = conn.getresponse()
                raw = resp.read()
                try:
                    self._jar.extract_cookies(resp, req)
                except Exception:
                    pass
                self._release(key, conn)
                return Response(resp.status, raw, None, dict(resp.getheaders()))
            except Exception as e:
                self._drop(conn)
                last_exc = e
                if attempt == 0:
                    continue
                raise RequestError(f'请求失败：{e}') from e
        raise RequestError(f'请求失败：{last_exc}')

    def request(self, method, url, body=None, headers=None, timeout=None, max_redirects=5):
        """
        执行一个请求，跟随重定向，返回 Response(status, body, url, headers)。
        """
        if not timeout:
            timeout = self._timeout
        headers = dict(headers or {})
        headers.setdefault('User-Agent', UA)
        original_method = method

        for _ in range(max_redirects + 1):
            parts = urllib.parse.urlsplit(url)
            scheme = parts.scheme.lower()
            if scheme not in ('http', 'https'):
                raise ValueError(f'不支持的协议：{scheme}')
            host = parts.hostname
            port = parts.port or (443 if scheme == 'https' else 80)
            path = parts.path or '/'
            if parts.query:
                path += '?' + parts.query
            key = (scheme, host, port)

            req = urllib.request.Request(url, data=body, headers=headers, method=method)
            self._jar.add_cookie_header(req)

            resp = self._round_trip(key, method, path, req, body, timeout)
            resp.url = url

            location = self._find_header(resp.headers, 'Location')
            if resp.status in self.REDIRECT_CODES and location:
                url = urllib.parse.urljoin(url, location)
                if resp.status in (301, 302, 303):
                    method, body = 'GET', None
                    headers.pop('Content-Type', None)
                continue
            return resp
        raise RequestError(f'重定向次数过多（初始方法 {original_method}）')


class Response:
    __slots__ = ('status', 'body', 'url', 'headers')

    def __init__(self, status, body, url, headers):
        self.status = status
        self.body = body
        self.url = url
        self.headers = headers

    def text(self):
        return self.body.decode('utf-8', 'replace')

    def json(self):
        return json.loads(self.text())


class RequestError(Exception):
    pass


SESSION = HttpSession(COOKIE_JAR, SSL_CONTEXT)

# 登录专用 opener（urllib 自带的重定向 + Cookie 管理足够 CAS 用）
_LOGIN_OPENER = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(COOKIE_JAR),
    urllib.request.HTTPSHandler(context=SSL_CONTEXT),
)
_LOGIN_OPENER.addheaders = [('User-Agent', UA)]

# 数据接口用的 opener（下载文件等，超时更长）
_DATA_OPENER = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(COOKIE_JAR),
    urllib.request.HTTPSHandler(context=SSL_CONTEXT),
)


def _login_get(url, timeout=30):
    """登录流程专用 GET，返回 (text, final_url)。"""
    with _LOGIN_OPENER.open(url, timeout=timeout) as r:
        return r.read().decode('utf-8', 'replace'), r.url


def _login_get_response(url, timeout=30):
    """登录流程专用 GET，返回完整响应 dict（含 status/url/headers/body）。"""
    with _LOGIN_OPENER.open(url, timeout=timeout) as r:
        body = r.read().decode('utf-8', 'replace')
        return {
            'status': r.status,
            'url': r.url,
            'headers': dict(r.headers),
            'body': body,
        }


def _login_get_json(url, timeout=30):
    """登录流程专用 GET JSON，用于取 RSA 公钥。"""
    with _LOGIN_OPENER.open(url, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8', 'replace'))


def _login_post_form(url, data: dict, timeout=30):
    """登录流程专用 POST form，返回 (text, final_url)。"""
    body = urllib.parse.urlencode(data).encode('utf-8')
    req = urllib.request.Request(
        url, data=body, method='POST',
        headers={'Content-Type': 'application/x-www-form-urlencoded'},
    )
    with _LOGIN_OPENER.open(req, timeout=timeout) as r:
        return r.read().decode('utf-8', 'replace'), r.url


def _get(url, timeout=DEFAULT_TIMEOUT):
    r = SESSION.request('GET', url, timeout=timeout)
    return r.text(), r.url


def _get_json(url, timeout=DEFAULT_TIMEOUT):
    return SESSION.request('GET', url, timeout=timeout).json()


def _post_form(url, data: dict, timeout=DEFAULT_TIMEOUT):
    body = urllib.parse.urlencode(data).encode('utf-8')
    r = SESSION.request('POST', url, body=body, timeout=timeout)
    return r.text(), r.url


def _post_json(url, obj: dict, timeout=60):
    body = json.dumps(obj).encode('utf-8')
    r = SESSION.request('POST', url, body=body, timeout=timeout,
                        headers={'Content-Type': 'application/json',
                                 'Accept': 'application/json'})
    return r.json()


def rsa_no_padding(password: str, modulus_hex: str, exponent_hex: str) -> str:
    """
    复刻浙大 CAS 前端 js 的加密方式：公钥 (modulus, exponent) + 无填充 RSA。
    算法：c = password_bytes ^ e mod m，结果转成十六进制。

    ⚠️ 关键点：密文的字节数**必须补齐到密钥长度**（512 bit -> 64 字节），
    也就是高位的前导零不能丢。如果按「最小长度」输出，一旦密文高位出现 0 字节
    （概率约 1/256，但对同一个密码是必现的），服务端就会判定密码错误。
    这一条跟 Python 版参考实现里的 `int2bytes(cypher, key_length)` 是对应的。
    """
    m = int(modulus_hex, 16)
    e = int(exponent_hex, 16)
    key_length = (m.bit_length() + 7) // 8
    x = int.from_bytes(password.encode('utf-8'), 'big')
    c = pow(x, e, m)
    return c.to_bytes(key_length, 'big').hex()


# 这些 cookie 名出现任意一个，就认为登录成功
AUTH_COOKIE_NAMES = ('iPlanetDirectoryPro', '_pm0', '_pf0', '_pc0',
                     'KEYCLOAK_SESSION', 'KEYCLOAK_SESSION_LEGACY',
                     'role_token', 'session')


def _has_auth_cookie() -> bool:
    """
    是否拿到了登录凭证 cookie。

    这比«看 URL 有没有离开登录页»更可靠：有时候 URL 没变但会话其实已建立，
    反过来也有 URL 跳走了但其实没成功的情况。两个信号里这个权重更高。
    """
    names = {c.name for c in COOKIE_JAR}
    return any(n in names for n in AUTH_COOKIE_NAMES)


def is_logged_in() -> bool:
    """会话是否还有效（CAS 未把请求打回登录页就算有效）。"""
    try:
        _, url = _login_get(HOME_URL, timeout=15)
        return 'cas/login' not in url
    except Exception:
        return False


def _warm_up_others():
    """
    后台种 eta 站点的 Cookie（成绩查询要用）。
    这步对「课程和作业」没有影响，放到后台慢慢跑，不再阻塞登录。
    """
    try:
        _get(ETA_URL, timeout=20)
    except Exception:
        pass
    save_session()


def _extract_execution(html: str, **ctx) -> str:
    """
    从 CAS 登录页 HTML 里抠出 execution 隐藏字段。

    不同版本的 CAS / 不同网络环境返回的 HTML 在属性顺序、引号、大小写上
    可能有差异，所以同时尝试多种正则，而不是只认一种写法。
    """
    patterns = [
        r'<input\b[^>]*?\bname=["\']execution["\'][^>]*?\bvalue=["\']([^"\']+)["\'][^>]*?>',
        r'<input\b[^>]*?\bvalue=["\']([^"\']+)["\'][^>]*?\bname=["\']execution["\'][^>]*?>',
    ]
    for p in patterns:
        m = re.search(p, html, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1)

    # 诊断信息（用于排错）：长度 / 状态 / 最终URL / 关键头 / 前800字符
    lower = html.lower()
    has_exec = 'execution' in lower
    preview = html[:800].replace('\n', ' ').replace('\r', ' ')
    info_parts = [f'响应长度 {len(html)}']
    if 'status' in ctx:
        info_parts.append(f'状态 {ctx["status"]}')
    if 'url' in ctx:
        info_parts.append(f'最终 URL {ctx["url"]}')
    if 'headers' in ctx:
        hdrs = ctx['headers']
        info_parts.append(
            f'Content-Type {hdrs.get("Content-Type", "N/A")}; Server {hdrs.get("Server", "N/A")}'
        )
    info_parts.append(f'含 execution 字样：{has_exec}')
    info_parts.append(f'前 800 字符：{preview!r}')
    raise RuntimeError('未能从登录页取到 execution 字段（' + '；'.join(info_parts) + '）')


def do_login(stuid: str, password: str, max_retries: int = 3) -> bool:
    """
    完整登录流程：

      1) 已登录则直接返回；
      2) GET 登录页，抠出隐藏字段 execution；
      3) GET 公钥接口，拿到 modulus / exponent；
      4) 密码 RSA 加密后，连同 execution 一起 POST 到 CAS；
      5) 成功后再访问一次首页，让服务端把业务 Cookie 种好。

    ⚠️ 为什么要重试（这是关键，浙大 CAS 的 Spring Webflow 需要）：
      CAS 用的是 Spring Webflow，第一轮 POST 有时会返回一个新的登录表单
      而不是直接通过。重新拿一次 execution 再提交，通常就成功了。

    ⚠️ 为什么第 2、3 步必须串行：
      CAS 是用 cookie 把「登录表单 execution」和「RSA 公钥」关联起来的，
      并发请求会让它们落到不同会话上，服务端直接判定登录失败。

    密码用完即从作用域消失，绝不落盘。
    """
    global CURRENT_STUID
    if is_logged_in():
        return True

    last_result = None
    for attempt in range(1, max_retries + 1):
        # 每次尝试都从干净的 cookie 状态开始（execution 与公钥必须同会话）
        COOKIE_JAR.clear()

        # 1) 登录页（拿 execution）
        resp = _login_get_response(LOGIN_URL, timeout=30)
        # 2) 公钥（与上一步串行，见 docstring）
        pk = _login_get_json(PUBKEY_URL, timeout=30)

        execution = _extract_execution(
            resp['body'], status=resp['status'], url=resp['url'], headers=resp['headers']
        )

        # 3) 密码加密
        rsapwd = rsa_no_padding(password, pk['modulus'], pk['exponent'])

        params = {
            'username': stuid,
            'password': rsapwd,
            'execution': execution,
            '_eventId': 'submit',
            'authcode': '',
            'rememberMe': 'true',
        }
        _, final_url = _login_post_form(LOGIN_URL, params, timeout=30)
        del rsapwd, params

        # 双信号判定：拿到凭证 cookie，或 URL 已离开登录页
        ok = _has_auth_cookie() or 'cas/login' not in final_url
        last_result = ok
        if ok:
            break
        if attempt < max_retries:
            safe_print(f'[登录] 第 {attempt} 次未通过，重试中…')
            time.sleep(0.8)

    if not last_result:
        return False

    # 4) 访问首页种业务 Cookie
    _login_get(HOME_URL, timeout=20)
    if not _has_auth_cookie():
        return False

    CURRENT_STUID = stuid  # 记住学号（成绩查询要用），随会话加密落盘
    save_session()
    threading.Thread(target=_warm_up_others, daemon=True).start()
    return True


# ---------------------------------------------------------------- 短缓存 ----
_CACHE = {}
_CACHE_LOCK = threading.Lock()
_INFLIGHT = {}
CACHE_TTL = 30


def cached(key, ttl, producer, force=False):
    """
    带 TTL 的缓存 + 并发合并（single-flight）。

    为什么需要「并发合并」：前端刷新时会同时请求 /api/courses 和 /api/homework，
    这两个接口都需要课程列表。如果各拉各的，同一份数据就被请求了两遍。
    有了下面的逻辑，同一份数据的并发请求只会真正发出**一次**网络请求，
    其它请求排队等这一份结果。

    为什么 force 也要写回缓存：force 只是说「这一次必须拿新的」，
    拿回来之后照样缓存起来，后面的请求就不用再拉了。
    """
    if not force:
        with _CACHE_LOCK:
            hit = _CACHE.get(key)
            if hit and time.time() - hit[0] < ttl:
                return hit[1]

    with _CACHE_LOCK:
        slot = _INFLIGHT.get(key)
        if slot is None:
            slot = {'event': threading.Event(), 'value': None, 'exc': None}
            _INFLIGHT[key] = slot
            leader = True
        else:
            leader = False

    if not leader:
        slot['event'].wait(timeout=90)
        if slot['exc']:
            raise slot['exc']
        return slot['value']

    try:
        slot['value'] = producer()
    except Exception as e:
        slot['exc'] = e
        raise
    finally:
        with _CACHE_LOCK:
            _INFLIGHT.pop(key, None)
        slot['event'].set()

    with _CACHE_LOCK:
        _CACHE[key] = (time.time(), slot['value'])
    return slot['value']


def invalidate_cache():
    with _CACHE_LOCK:
        _CACHE.clear()


# ---------------------------------------------------------------- 数据接口 ----

def norm_semester(name):
    """
    把半学期名称归并到对应的长学期（用户习惯：春/夏/春夏统称「春夏」长学期，
    秋/冬统称「秋冬」长学期），例如：
      2024-2025春 / 2024-2025夏 / 2024-2025春夏 → 2024-2025春夏
      2024-2025秋 / 2024-2025冬 / 2024-2025秋冬 → 2024-2025秋冬
    「短」学期与已是长学期的名称原样保留。
    """
    if not name:
        return name
    if name.endswith('秋冬') or name.endswith('春夏'):
        return name
    if name.endswith('秋'):
        return name + '冬'
    if name.endswith('冬'):
        return name[:-1] + '秋冬'
    if name.endswith('春') or name.endswith('夏'):
        return name[:-1] + '春夏'
    return name


def get_semesters(force=False):
    def produce():
        data = _get_json(SEMESTERS_URL, timeout=20)
        return data.get('semesters', [])
    return cached('semesters', CACHE_TTL, produce, force=force)


def courses_url(statuses):
    """拼出「我的课程」接口。statuses 里传什么状态，就返回什么范围的课程。"""
    cond = {'status': statuses, 'keyword': '', 'display_studio_list': False}
    return ('https://courses.zju.edu.cn/api/my-courses?' +
            urllib.parse.urlencode({
                'conditions': json.dumps(cond, separators=(',', ':')),
                'fields': 'id,name,semester_id,course_attributes',
                'page': 1,
                'page_size': 1000,
            }))


def _fetch_teachers(course_ids):
    """
    并发拉各门课程详情，提取授课教师（instructors）姓名，course_id -> '老师A、老师B'。
    单门课拉不到（网络抖动等）就给空串，不拖垮整体。
    """
    def one(cid):
        try:
            d = _get_json('https://courses.zju.edu.cn/api/courses/%s' % cid, timeout=15)
            names = [(i.get('name') or '').strip()
                     for i in (d.get('instructors') or [])]
            return '、'.join(n for n in names if n)
        except Exception:
            return ''

    out = {}
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(one, cid): cid for cid in course_ids}
        for fut in as_completed(futs):
            out[futs[fut]] = fut.result()
    return out


def get_courses(force=False):
    """
    拉取**全部学期**的课程（含已结束）。

    万一服务端不接受 "ended" 这个状态导致返回空，会自动退回到只查在学期，
    保证永远不会「一学期都看不到」。
    """
    def produce():
        semesters = get_semesters(force=force)
        names = {s['id']: s.get('name', '') for s in semesters}
        active_ids = {s['id'] for s in semesters if s.get('is_active')}

        rows = []
        for statuses in (COURSE_STATUS_ALL, ['ongoing', 'notStarted']):
            try:
                data = _get_json(courses_url(statuses), timeout=25)
                rows = data.get('courses') or []
            except Exception:
                rows = []
            if rows:
                break

        out = []
        for c in rows:
            sid = c.get('semester_id')
            out.append({
                'id': c.get('id'),
                'name': c.get('name', ''),
                'semester_id': sid,
                'semester_name': norm_semester(names.get(sid, '')),
                'is_active': sid in active_ids,
                'teaching_class': (c.get('course_attributes') or {}).get('teaching_class_name', ''),
            })

        # 授课教师：只存在于单门课程详情里。教师几乎不变，单独长缓存 1 天；
        # 若课程列表出现新 id（缓存里没有），强制刷新一次教师缓存。
        ids = [c['id'] for c in out]
        if ids:
            teachers = cached('teachers_v1', 86400, lambda: _fetch_teachers(ids))
            if any(i not in teachers for i in ids):
                teachers = cached('teachers_v1', 86400,
                                  lambda: _fetch_teachers(ids), force=True)
            for c in out:
                c['teacher'] = teachers.get(c['id'], '')
        return out
    return cached('courses', CACHE_TTL, produce, force=force)


def _parse_dt(s):
    """把 '2026-09-14T04:00:00Z' 这类时间解析成带 UTC 时区的 datetime；失败返回 None。"""
    if not s:
        return None
    text = str(s).strip()
    if text.endswith('Z') or text.endswith('z'):
        text = text[:-1] + '+00:00'
    try:
        return datetime.datetime.fromisoformat(text)
    except Exception:
        return None


def homework_status(h):
    """
    按起止时间把作业分成三类：not_started（未开始）/ ongoing（进行中）/ ended（已结束）。
    浙大返回的 is_closed 带排课含义（还没开始的作业也可能是 True），不可直接当作
    「已结束」，所以只用时间判断；没有时间信息时默认 ongoing（与旧行为一致）。
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    start = _parse_dt(h.get('start_time'))
    end = _parse_dt(h.get('end_time') or h.get('deadline'))
    if start and now < start:
        return 'not_started'
    if end and now > end:
        return 'ended'
    return 'ongoing'


def get_homework(course_id, course_name, include_closed):
    """拉取某门课的作业活动。"""
    url = (f'https://courses.zju.edu.cn/api/courses/{course_id}'
           f'/homework-activities?page=1&page_size=1000')
    data = _get_json(url, timeout=25)
    out = []
    for h in data.get('homework_activities', []):
        if h.get('is_closed') and not include_closed:
            continue
        out.append({
            'id': h.get('id'),
            'course_id': course_id,
            'title': h.get('title', ''),
            'course': course_name,
            'deadline': h.get('deadline'),
            'start_time': h.get('start_time'),
            'end_time': h.get('end_time'),
            'status': homework_status(h),
            'submitted': h.get('submitted', False),
            'description': html.unescape((h.get('data') or {}).get('description') or '').strip(),
        })
    return out


def get_all_homework(courses, only_active=False, workers=8, include_closed=False):
    """
    汇总所有课程的作业，并且**并行**拉取。

    这是提速最大的一步：以前是 N 门课排成一队，每门几百毫秒，加起来好几秒；
    现在同时并发请求，总时间约等于「最慢的那一次请求」。
    """
    targets = [c for c in courses if c['is_active'] or not only_active]
    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets) or 1))) as pool:
        futures = {pool.submit(get_homework, c['id'], c['name'], include_closed): c
                   for c in targets}
        for fut in as_completed(futures):
            c = futures[fut]
            try:
                results.extend(fut.result())
            except Exception as ex:
                safe_print(f'获取《{c["name"]}》作业失败: {ex}')
    results.sort(key=lambda x: (x['submitted'], x['deadline'] or '9999'))
    return results


def get_course_homework(course_id, course_name, force=False):
    """
    拉取**某门课**的作业活动，并对「已提交」的作业尽量补上提交详情
    （提交时间、分数/成绩、教师评语、自己提交的文件）。

    接口与 fiz 的 homework.rs 一致：
      courses/{id}/homework-activities?page=1&page_size=1000
    提交详情（best-effort，失败不影响主流程）走 fiz 提交时用的同一接口：
      course/activities/{id}/submissions  （GET，返回该作业的全部提交版本）

    学在浙大允许学生多次提交，官方页用「提交版本」下拉切换查看每次的历史
    （时间/成绩/评语/附件，还有老师的批改附件 submission_correct.uploads）。
    因此这里把全部版本解析进 item['submissions']；最上面一条（官方认为的最新版）
    仍同时平铺成 item['submitted_at']/grade/comment/submitted_uploads 供旧前端逻辑使用。
    """
    def produce():
        url = (f'https://courses.zju.edu.cn/api/courses/{course_id}'
               f'/homework-activities?page=1&page_size=1000')
        data = _get_json(url, timeout=25)

        # 提交记录：用官方前端同款的「课程级」接口一次拉全（比逐个作业请求快），
        #   GET /api/course/{course_id}/submissions
        # 返回 {"submissions": [...]}，每条含 activity_id/comment/instructor_comment/
        # score/final_score/uploads(name,size,deleted) 等。
        # 注意：老代码用的 /api/course/activities/{id}/submissions 实际返回的是网页
        # 而非 JSON，这就是「已提交却显示不出文件」的根因。
        sub_map = {}
        try:
            sresp = SESSION.request(
                'GET', f'https://courses.zju.edu.cn/api/course/{course_id}/submissions',
                timeout=25)
            sdata = json.loads(sresp.body.decode('utf-8', 'replace'))
            for s in sdata.get('submissions') or []:
                aid = s.get('activity_id')
                if aid:
                    sub_map.setdefault(aid, []).append(s)
        except Exception:
            pass

        def _parse_uploads(rec):
            return [{'id': u.get('id'),
                     'reference_id': u.get('reference_id'),
                     'name': (u.get('name') or '').strip(),
                     'size': u.get('size')}
                    for u in (rec.get('uploads') or [])
                    if not u.get('deleted')]

        def _parse_marked(submission_id):
            """老师批改附件（best-effort）：GET /api/submissions/{id}/marked_attachments
            返回 marked_attachment_infos: [{marked_attachment, origin_upload}]，
            未批改时 marked_attachment 为空对象。"""
            try:
                mresp = SESSION.request(
                    'GET', (f'https://courses.zju.edu.cn/api/submissions/'
                            f'{submission_id}/marked_attachments'),
                    timeout=20)
                mdata = json.loads(mresp.body.decode('utf-8', 'replace'))
                files = []
                for mi in mdata.get('marked_attachment_infos') or []:
                    ma = mi.get('marked_attachment') or {}
                    if ma.get('id'):
                        files.append({'id': ma.get('id'),
                                      'reference_id': ma.get('reference_id'),
                                      'name': (ma.get('name') or '批改附件').strip(),
                                      'size': ma.get('size')})
                return files
            except Exception:
                return []

        out = []
        for h in data.get('homework_activities') or []:
            uploads = [{'id': u.get('id'), 'reference_id': u.get('reference_id'),
                        'name': (u.get('name') or '').strip(),
                        'size': u.get('size')}
                       for u in h.get('uploads') or []]

            item = {
                'id': h.get('id'),
                'title': (h.get('title') or '').strip(),
                'course': course_name,
                'deadline': h.get('deadline'),
                'start_time': h.get('start_time'),
                'end_time': h.get('end_time'),
                'is_closed': h.get('is_closed', False),
                'status': homework_status(h),
                'submitted': h.get('submitted', False),
                'description': html.unescape((h.get('data') or {}).get('description') or '').strip(),
                'uploads': uploads,
                'submitted_at': None,
                'grade': None,
                # 官方同款：is_announce_score_time_passed 表示成绩是否已公布，
                # 公布后作业对象上的 score 字段就是最终成绩
                'score_published': bool(h.get('is_announce_score_time_passed') or
                                        h.get('score_published')),
                'activity_score': h.get('score'),
                'comment': '',
                'submitted_uploads': [],
                'submissions': [],
            }
            if item['submitted']:
                recs = sub_map.get(item['id']) or []
                recs.sort(key=lambda s: s.get('created_at') or '', reverse=True)
                for idx, rec in enumerate(recs):
                    s_uploads = _parse_uploads(rec)
                    # 批改附件只对最新一条查询，减少请求数（历史版本一般不会再批改）
                    correct_uploads = (_parse_marked(rec['id'])
                                       if idx == 0 and rec.get('id') else [])
                    sgrade = (rec.get('score') if rec.get('score') is not None
                              else (rec.get('final_score') if rec.get('final_score') is not None
                                    else rec.get('grade')))
                    # 提交记录未出分时，回退到作业对象上已下发的成绩（浙大只在
                    # 老师登分后才下发 score，没分时为 None）
                    if sgrade is None and item['activity_score'] is not None:
                        sgrade = item['activity_score']
                    item['submissions'].append({
                        'submitted_at': (rec.get('created_at') or
                                         rec.get('submitted_at') or
                                         rec.get('updated_at')),
                        'grade': sgrade,
                        'comment': rec.get('comment') or '',
                        'instructor_comment': rec.get('instructor_comment') or '',
                        'uploads': s_uploads,
                        'correct_uploads': correct_uploads,
                    })
                # 最新一条平铺成旧字段，保持向前兼容
                if recs:
                    rec = recs[0]
                    item['submitted_at'] = (rec.get('created_at') or
                                            rec.get('submitted_at') or
                                            rec.get('updated_at'))
                    grade = (rec.get('score') if rec.get('score') is not None
                             else (rec.get('final_score') if rec.get('final_score') is not None
                                   else rec.get('grade')))
                    # 提交记录里没出分时，回退用作业对象上下发的成绩
                    if grade is None and item['activity_score'] is not None:
                        grade = item['activity_score']
                    item['grade'] = grade
                    item['comment'] = rec.get('instructor_comment') or ''
                    item['submitted_uploads'] = _parse_uploads(rec)
            out.append(item)
        return out
    return cached('coursehw:%s' % course_id, CACHE_TTL, produce, force=force)


def get_modules(course_id, force=False):
    """
    拉取某门课的「章节(module)列表」——这就是学在浙大网页版的大章节。

    接口：GET /api/courses/{course_id}/modules
    返回：{ "modules": [ {id, name, sort, ...} ] }
    其中 module.name 就是网页版显示的章节标题（如「第一章 信息素质与AI基础」、
    「Chapter 1. Introduction」），原封不动采用，不做任何推断。

    coursewares 接口里每个 activity 都带 module_id，指向上面的某个 module，
    因此用 module_id 把活动归组即可得到与网页版一致的章节划分。
    """
    def produce():
        url = 'https://courses.zju.edu.cn/api/courses/%s/modules?page=1&page_size=1000' % course_id
        data = _get_json(url, timeout=30)
        out = []
        for m in data.get('modules') or []:
            out.append({
                'id': m.get('id'),
                'name': (m.get('name') or '').strip(),
                'sort': m.get('sort') or 0,
            })
        return out
    return cached('modules:%s' % course_id, CACHE_TTL, produce, force=force)


def get_courseware(course_id, force=False):
    """
    拉取某门课的「章节 + 资源文件」，并按学在浙大网页版真实的 module（章节）归组。

    两个接口：
      · /api/courses/{id}/modules       → 章节列表（module_id + 真实章节名 + 排序）
      · /api/course/{id}/coursewares     → 活动平铺列表（每个 activity 含 module_id + uploads）
    用 activity.module_id 匹配 module.id，章节标题原封不动用 module.name。
    """
    def produce():
        cond = {
            'category': None,
            'itemsSortBy': {'predicate': 'chapter', 'reverse': False},
            'ignore_activity_types': ['lesson'],
        }
        url = (f'https://courses.zju.edu.cn/api/course/{course_id}'
               f'/coursewares?page=1&page_size=1000&conditions='
               f'{urllib.parse.quote(json.dumps(cond, separators=(",", ":")))}')
        data = _get_json(url, timeout=30)

        activities = []
        for a in data.get('activities') or []:
            ups = []
            for u in a.get('uploads') or []:
                ups.append({'id': u.get('id'), 'reference_id': u.get('reference_id'),
                            'name': (u.get('name') or '').strip()})
            activities.append({
                'id': a.get('id'),
                'title': (a.get('title') or '').strip(),
                'uploads': ups,
                'type': (a.get('type') or '').strip() or None,
                'activity_type': (a.get('activity_type') or '').strip() or None,
                'module_id': a.get('module_id'),
            })

        mods = get_modules(course_id)
        chapters = []
        for m in sorted(mods, key=lambda x: x.get('sort', 0)):
            chapters.append({
                'no': m['id'],
                'title': m['name'],
                'module_id': m['id'],
                'activities': [],
            })
        cmap = {c['module_id']: c for c in chapters}
        orphan = {'no': 0, 'title': '未分类资料', 'module_id': None, 'activities': []}
        for a in activities:
            mid = a.get('module_id')
            if mid in cmap:
                cmap[mid]['activities'].append(a)
            else:
                orphan['activities'].append(a)
        chapters = [c for c in chapters if c['activities']]
        if orphan['activities']:
            chapters.append(orphan)
        return {'activities': activities, 'chapters': chapters}
    return cached('courseware:%s' % course_id, CACHE_TTL, produce, force=force)


_CN = {'一': 1, '二': 2, '三': 3, '四': 4, '五': 5,
       '六': 6, '七': 7, '八': 8, '九': 9, '十': 10}
_CN_REV = {v: k for k, v in _CN.items()}


def _cn_num(text):
    """把「三」「十二」「二十」等中文数字转成 int，失败返回 None。"""
    text = (text or '').strip()
    if not text:
        return None
    if text.isdigit():
        return int(text)
    if text in _CN_REV:
        return _CN_REV[text]
    m = re.match(r'^([二三四五六七八九十]+)$', text)
    if not m:
        return None
    s = text
    if '十' in s:
        parts = s.split('十')
        if len(parts) == 2:
            tens = _CN_REV.get(parts[0], 1) if parts[0] else 1
            ones = _CN_REV.get(parts[1], 0) if parts[1] else 0
            return tens * 10 + ones
        return _CN_REV.get(s, None)
    return None


def _extract_chapter(activity):
    """
    从课件类 activity 的标题或文件名里推断章号，并给出章节显示标题。
    命中规则（按优先级）：
      1) 第N章 / 第N章(中文)      → 第N章 [副标题]
      2) Chapter N / Chapter N. Title → Chapter N. Title（保留原标题）
      3) 课件N                    → 第N章
    返回 {"no": int, "title": str}；非课件类返回 None。
    """
    title = activity.get('title') or ''
    names = ' '.join((u.get('name') or '') for u in activity.get('uploads') or [])
    text = title + ' ' + names

    # 1) 阿拉伯数字「第N章」
    m = re.search(r'第\s*([0-9]+)\s*章', text)
    if m:
        no = int(m.group(1))
        sub = re.split(r'第\s*[0-9]+\s*章', text, maxsplit=1)[-1].strip(' .-—')
        return {'no': no,
                'title': f'第{_CN.get(no, str(no))}章{(" " + sub) if sub else ""}'}

    # 2) 中文数字「第N章」
    m = re.search(r'第\s*([一二三四五六七八九十]+)\s*章', text)
    if m:
        no = _cn_num(m.group(1))
        if no:
            sub = re.split(r'第\s*[一二三四五六七八九十]+\s*章', text, maxsplit=1)[-1].strip(' .-—')
            return {'no': no,
                    'title': f'第{_CN.get(no, str(no))}章{(" " + sub) if sub else ""}'}

    # 3) 英文 Chapter N
    m = re.search(r'\bChapter\s*([0-9]+)(?:\s*[.:]?\s*)([^\n]*)', text, re.IGNORECASE)
    if m:
        no = int(m.group(1))
        sub = m.group(2).strip()
        # 标题本身就是「Chapter N」形式 → 保留原标题
        if title and re.match(r'Chapter\s*[0-9]+', title, re.IGNORECASE):
            return {'no': no, 'title': title.strip()}
        return {'no': no,
                'title': 'Chapter %d%s' % (no, ('. ' + sub) if sub else '')}

    # 4) 课件N
    m = re.search(r'课件\s*([0-9]+)', title)
    if m:
        no = int(m.group(1))
        return {'no': no, 'title': '第%s章' % _CN.get(no, str(no))}
    return None


def _group_courseware(activities):
    """
    按浙大网页版的规则把平铺 activities 归组成大章节：
    - 遇到课件类活动（能从标题/文件名推断章号）→ 开新章；
    - 其余活动挂在「最近遇到的章」下；
    - 出现在第一个课件之前的活动 → 归到「课前资料」。
    """
    chapters = []
    cur = None
    for a in activities:
        ch = _extract_chapter(a)
        if ch:
            cur = {'no': ch['no'], 'title': ch['title'], 'activities': []}
            chapters.append(cur)
        elif cur is None:
            cur = {'no': 0, 'title': '课前资料', 'activities': []}
            chapters.append(cur)
        cur['activities'].append(a)
    chapters.sort(key=lambda c: c['no'])
    return chapters


def stream_upload(upload_id):
    """
    打开学在浙大文件 blob 的**流式**响应（与登录共用同一份 Cookie）。

    用内置 urllib 一边读一边写给浏览器，避免大 PPT/Word 把内存占满。
    """
    url = 'https://courses.zju.edu.cn/api/uploads/%s/blob' % upload_id
    req = urllib.request.Request(url, headers={'User-Agent': UA, 'Accept': '*/*'})
    COOKIE_JAR.add_cookie_header(req)
    return _DATA_OPENER.open(req, timeout=120)


def api_save_download(upload_id, name, course=''):
    """
    把学在浙大文件**直接写到本地下载文件夹**（桌面版专用）。

    桌面外壳（pywebview/WebView2）不支持网页触发的「另存为」，所以由后端
    一边流式拉取一边落盘。同名文件自动加 (1)、(2) 后缀，绝不覆盖。
    course 非空时落到「下载文件夹/课程名/」子文件夹（借鉴 fiz 的整理方式）。
    """
    folder = get_download_dir()
    sub = re.sub(r'[\\/:*?"<>|]', '_', (course or '').strip()).strip('. ')
    if sub:
        folder = os.path.join(folder, sub)
        os.makedirs(folder, exist_ok=True)
    fname = os.path.basename(name or '').strip() or ('file_%s' % upload_id)
    fname = re.sub(r'[\\/:*?"<>|]', '_', fname)   # Windows 非法字符
    stem, ext = os.path.splitext(fname)
    target = os.path.join(folder, fname)
    n = 1
    while os.path.exists(target):
        target = os.path.join(folder, '%s(%d)%s' % (stem, n, ext))
        n += 1
    try:
        resp = stream_upload(upload_id)
        with open(target, 'wb') as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)
    except Exception as e:
        try:
            os.remove(target)   # 写一半失败的残片清掉
        except Exception:
            pass
        return {'ok': False, 'error': '下载失败：' + str(e)}
    return {'ok': True, 'path': target}


def api_open_download_dir():
    """在资源管理器里打开当前下载文件夹（本地服务与用户同机，有此权限）。"""
    folder = get_download_dir()
    try:
        os.makedirs(folder, exist_ok=True)
    except Exception:
        pass
    if not os.path.isdir(folder):
        return {'ok': False, 'error': '文件夹不存在：' + folder}
    try:
        if os.name == 'nt':
            subprocess.Popen(['explorer', folder])
        else:
            subprocess.Popen(['xdg-open', folder])
        return {'ok': True}
    except Exception as e:
        return {'ok': False, 'error': '无法打开：' + str(e)}


# ---------------------------------------------------------------- 智云课堂 ----
# 课堂直录播列表 + 「导出课件(PPT)」。
# 链路：学在浙大课程 → 课堂直录播标签(extension-lives) → 智云课堂回放页
#       → 官方「导出课件」接口（与网页端按钮完全同源，产物是原生 PPT/PDF）。
#
# 免登原理：登录学在浙大时 iPlanetDirectoryPro 等域级 SSO Cookie 已覆盖
# *.zju.edu.cn；访问 tgmedia.cmc.zju.edu.cn 的 auth/login 跳转即可免密换取
# 智云课堂自己的 _token（Cookie 里是一段 PHP 会话串，解出 JWT 作 Bearer）。

CMC_BASE = 'https://classroom.zju.edu.cn'


def _cmc_bearer_token(page_view_url=''):
    """
    取智云课堂的 Bearer JWT：优先解会话里已有的 _token Cookie；
    没有就走一次 tgmedia 免登跳转把它换回来（全程不需要密码）。
    """
    def _unpack():
        for c in COOKIE_JAR:
            if c.name == '_token' and 'zju.edu.cn' in (c.domain or ''):
                # Cookie 形如 _token"...;s:733:"eyJhbGciOi...";} → 解出 JWT
                m = re.search(r's:\d+:"(eyJ[^"]+)"',
                              urllib.parse.unquote(c.value or ''))
                if m:
                    return m.group(1)
                v = (c.value or '').strip()
                if v.startswith('eyJ'):
                    return v
        return ''

    tok = _unpack()
    if tok:
        return tok
    m = re.search(r'tenant_code=(\d+)', page_view_url or '')
    tenant = m.group(1) if m else '112'
    fwd = page_view_url or (CMC_BASE + '/')
    login = ('https://tgmedia.cmc.zju.edu.cn/index.php?r=auth/login&auType='
             '&tenant_code=' + tenant + '&forward=' +
             urllib.parse.quote(fwd, safe=''))
    try:
        HttpSession(COOKIE_JAR, SSL_CONTEXT, timeout=30).request('GET', login)
    except Exception:
        pass
    save_session()          # 换到的 _token 顺手持久化，下次不用再换
    return _unpack()


def _fetch_lives(course_id):
    """拉某门课的课堂直录播列表（学在浙大 extension-lives 接口）。"""
    data = _get_json('https://courses.zju.edu.cn/api/courses/%s/extension-lives'
                     '?source=chinamcloud_live' % course_id)
    lives = (data.get('lives') if isinstance(data, dict) else None) or []
    out = []
    for l in lives:
        try:
            dur = int(float(l.get('sub_duration') or 0))
        except Exception:
            dur = 0
        out.append({
            'sub_id': str(l.get('sub_id') or ''),
            'title': l.get('title') or '',
            'start_time': l.get('start_time') or '',
            'status': l.get('status') or '',
            'duration_min': int(dur / 60) if dur else 0,
            'page_view_url': l.get('page_view_url') or '',
        })
    out.sort(key=lambda x: x['start_time'], reverse=True)
    return out


def api_course_lives(course_id):
    try:
        cid = int(course_id)
    except Exception:
        return {'ok': False, 'error': 'course_id 无效'}
    try:
        lives = cached('lives_v1_%s' % cid, 21600, lambda: _fetch_lives(cid))
        return {'ok': True, 'lives': lives}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def export_live_ppt(sub_id, page_view_url, course='', fallback_name=''):
    """
    导出某节录播的课件（type=1 → PPT），保存到下载文件夹/课程名/ 下。

    完全复刻智云课堂网页端「导出课件(PPT)」按钮的逻辑：
      1. get-courseware-status：code=0 表示已生成，直接拿 file_name/path_name；
      2. 否则 export-async 发起异步生成，每 10 秒轮询一次（同官方前端）；
      3. 生成完拿签名直链下载落盘。
    """
    bearer = _cmc_bearer_token(page_view_url)
    if not bearer:
        return {'ok': False, 'error': '未能取得智云课堂登录凭证，请重新登录后再试'}
    h = HttpSession(COOKIE_JAR, SSL_CONTEXT, timeout=60)
    hdr = {'Authorization': 'Bearer ' + bearer}

    def query_status():
        r = h.request(
            'GET', CMC_BASE + '/courseapi/v2/export/get-courseware-status'
            '?type=1&sub_id=%s&get_source_url=1' % sub_id, headers=hdr)
        return r.json()

    def dl_file():
        info = d.get('data')
        if not isinstance(info, dict):
            return {'ok': False, 'error': '智云课堂未返回课件信息'}
        file_name = (info.get('file_name') or '').strip()
        path_name = (info.get('path_name') or '').strip()
        if not path_name:
            return {'ok': False, 'error': '智云课堂未返回下载地址'}
        folder = get_download_dir()
        sub = re.sub(r'[\\/:*?"<>|]', '_', (course or '').strip()).strip('. ')
        if sub:
            folder = os.path.join(folder, sub)
        os.makedirs(folder, exist_ok=True)
        fname = file_name or (fallback_name or ('智云课件_%s.pptx' % sub_id))
        fname = re.sub(r'[\\/:*?"<>|]', '_', os.path.basename(fname)).strip()
        if not fname:
            fname = '智云课件_%s.pptx' % sub_id
        if '.' not in fname:
            fname += '.pptx'
        stem, ext = os.path.splitext(fname)
        target = os.path.join(folder, fname)
        n = 1
        while os.path.exists(target):
            target = os.path.join(folder, '%s(%d)%s' % (stem, n, ext))
            n += 1
        url = path_name if path_name.startswith('http') else CMC_BASE + path_name
        try:
            resp = h.request('GET', url, headers=hdr)
            if resp.status != 200 or not resp.body:
                return {'ok': False, 'error': '课件下载失败（HTTP %s）' % resp.status}
            with open(target, 'wb') as f:
                f.write(resp.body)
        except Exception as e:
            try:
                os.remove(target)
            except Exception:
                pass
            return {'ok': False, 'error': '课件下载失败：' + str(e)}
        return {'ok': True, 'path': target}

    # 1) 查一次状态；code=0 已生成可直接下
    d = query_status()
    if d.get('code') == 0:
        return dl_file()
    if d.get('code') not in (1, 200):
        return {'ok': False,
                'error': '该节录播暂无可导出的课件：' + str(d.get('msg') or d.get('code'))}

    # 2) 发起异步生成并轮询（官方前端同样是 10 秒一查，这里最多等 4 分钟）
    r2 = h.request(
        'GET', CMC_BASE + '/courseapi/v2/export/export-async'
        '?sub_id=%s&export_type=courseware&type=1' % sub_id, headers=hdr)
    d2 = r2.json()
    if d2.get('code') != 0:
        return {'ok': False, 'error': '发起课件生成失败：' + str(d2.get('msg') or d2.get('code'))}
    deadline = time.time() + 240
    while time.time() < deadline:
        time.sleep(10)
        try:
            d = query_status()
        except Exception:
            continue
        if d.get('code') == 0:
            return dl_file()
        if d.get('code') not in (1, 200):
            return {'ok': False, 'error': '课件生成失败：' + str(d.get('msg') or d.get('code'))}
    return {'ok': False, 'error': '课件生成超时（长节课要几分钟），请稍后重试'}


# ---------------------------------------------------------------- 文件夹选择 ----
# 浏览器模式下前端拿不到系统目录路径，就由本地服务（它就在用户电脑上跑）
# 代为弹出 Windows 原生「选择文件夹」对话框（资源管理器同款 IFileDialog）。

def pick_folder_native():
    """
    弹出 Windows 原生「选择文件夹」对话框，阻塞到用户选完/取消。

    返回 {'ok': True, 'dir': '...'} / {'ok': True, 'cancelled': True}
       / {'ok': False, 'error': '...'}
    """
    if os.name != 'nt':
        return {'ok': False, 'error': '当前系统不支持弹出文件夹选择窗口'}
    import ctypes
    from ctypes import byref, c_uint, c_ubyte, c_ushort, c_ulong, c_void_p, POINTER

    class _GUID(ctypes.Structure):
        _fields_ = [('Data1', c_ulong), ('Data2', c_ushort),
                    ('Data3', c_ushort), ('Data4', c_ubyte * 8)]

    def _guid(s):
        p = s.strip('{}').split('-')
        d4 = ([int(p[3][0:2], 16), int(p[3][2:4], 16)] +
              [int(p[4][i:i + 2], 16) for i in range(0, 12, 2)])
        return _GUID(int(p[0], 16), int(p[1], 16), int(p[2], 16),
                     (c_ubyte * 8)(*d4))

    class _Item(ctypes.Structure):      # COM 接口指针的最小占位
        _fields_ = [('lpVtbl', c_void_p)]

    CLSID_FileOpenDialog = _guid('{DC1C5A9C-E88A-4DDE-A5A1-60F82A20AEF7}')
    IID_IFileOpenDialog = _guid('{D57C7288-D4AD-4768-BE02-9D969532D960}')
    SIGDN_FILESYSPATH = 0x80058000
    FOS_PICKFOLDERS = 0x20
    FOS_FORCEFILESYSTEM = 0x40
    CANCELLED = 0x800704C7              # 用户点取消时的 HRESULT

    ole32 = ctypes.WinDLL('ole32')
    user32 = ctypes.WinDLL('user32')

    def _slot(obj, index, *argtypes):
        """取 COM 对象 vtable 第 index 个方法（返回 HRESULT，首参固定为接口指针）。"""
        tbl = ctypes.cast(obj[0].lpVtbl, ctypes.POINTER(c_void_p))
        return ctypes.WINFUNCTYPE(ctypes.HRESULT, c_void_p, *argtypes)(tbl[index])

    def _call(fn, *args):
        """ctypes 对 HRESULT 失败会抛 OSError；统一转为返回码。"""
        try:
            return fn(*args)
        except OSError as e:
            return e.winerror or -1

    try:
        ole32.CoInitializeEx(None, 2)   # APARTMENTTHREADED；已初始化则忽略
    except Exception:
        pass

    pdlg = POINTER(_Item)()
    hr = ole32.CoCreateInstance(byref(CLSID_FileOpenDialog), None, 1,
                                byref(IID_IFileOpenDialog), byref(pdlg))
    if hr != 0:
        return {'ok': False,
                'error': '无法创建文件夹选择窗口 (0x%08X)' % (hr & 0xFFFFFFFF)}
    try:
        # 标题写明用途（IFileDialog 虚表：17=SetTitle）
        _call(_slot(pdlg, 17, ctypes.c_wchar_p),
              pdlg, '选择 ZJU-Course 的下载文件夹')
        hr = _slot(pdlg, 9, c_uint)(pdlg, FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM)
        if hr != 0:
            return {'ok': False, 'error': '初始化选择窗口失败 (0x%08X)' % (hr & 0xFFFFFFFF)}

        # 挂到当前活动窗口上（避免被埋到别的窗口后面）；失败则退回无主窗口
        hwnd = user32.GetForegroundWindow()
        hr = _call(_slot(pdlg, 3, c_void_p), pdlg, hwnd)   # Show：阻塞到用户操作
        if hr != 0 and (hr & 0xFFFFFFFF) != CANCELLED:
            hr = _call(_slot(pdlg, 3, c_void_p), pdlg, None)
        if hr != 0:
            if (hr & 0xFFFFFFFF) == CANCELLED:
                return {'ok': True, 'cancelled': True}
            return {'ok': False, 'error': '选择窗口被关闭 (0x%08X)' % (hr & 0xFFFFFFFF)}

        pitem = c_void_p()
        # IFileDialog 虚表：3=Show 9=SetOptions 20=GetResult 21=AddPlace 23=Close
        hr = _slot(pdlg, 20, POINTER(c_void_p))(pdlg, byref(pitem))  # GetResult
        if hr != 0 or not pitem:
            return {'ok': False,
                    'error': '未取得所选文件夹 (0x%08X)' % (hr & 0xFFFFFFFF)}
        try:
            itbl = ctypes.cast(ctypes.cast(pitem, POINTER(_Item))[0].lpVtbl,
                               ctypes.POINTER(c_void_p))
            get_name = ctypes.WINFUNCTYPE(ctypes.HRESULT, c_void_p, c_uint,
                                          POINTER(ctypes.c_wchar_p))(itbl[5])
            buf = ctypes.c_wchar_p()
            hr = get_name(pitem, SIGDN_FILESYSPATH, byref(buf))
            if hr != 0 or not buf.value:
                return {'ok': False, 'error': '无法读取所选路径'}
            return {'ok': True, 'dir': buf.value}
        finally:
            _slot(ctypes.cast(pitem, POINTER(_Item)), 2)(pitem)      # Release
    finally:
        _slot(pdlg, 2)(pdlg)                                          # Release


def _pick_dir_via_child():
    """
    在**独立子进程**里弹原生选文件夹窗口，结果经临时文件回传。

    好处：GUI/COM 层面出任何意外（崩溃、卡死）都不会连累主服务——
    最多这一次选择失败，页面拿到的仍是正常的 JSON 错误。
    """
    import tempfile
    out_path = os.path.join(tempfile.gettempdir(), 'zjucourse_pick_%d.json'
                            % secrets.randbelow(10 ** 9))
    try:
        if IS_FROZEN:
            cmd = [sys.executable, '--pick-dir-child', out_path]
        else:
            cmd = [sys.executable, os.path.abspath(__file__),
                   '--pick-dir-child', out_path]
        flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        p = subprocess.run(cmd, timeout=600, capture_output=True,
                           creationflags=flags)
        try:
            with open(out_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
        return {'ok': False,
                'error': '选择窗口未正常返回（退出码 %s）' % p.returncode}
    except subprocess.TimeoutExpired:
        return {'ok': False, 'error': '选择窗口超时未关闭（10 分钟）'}
    except Exception as e:
        return {'ok': False, 'error': '打开选择窗口失败：' + str(e)}
    finally:
        try:
            os.remove(out_path)
        except Exception:
            pass


# 在线预览转出来的文件超过这个大小就提示下载，不再硬塞进内存/浏览器
PREVIEW_MAX_BYTES = 100 * 1024 * 1024


def fetch_preview_bytes(upload_id):
    """
    带登录会话拉取「学在浙大在线预览服务」转好的内容，返回 (bytes, content_type)。

    流程（与 fiz 的 preview.rs 相同）：
      1. GET /api/uploads/document/{id}/url?preview=true  → 签名预览地址；
      2. 用**我们的登录会话**再去 GET 那个地址取内容。
         浙大服务端会：Word/PPT/Excel → PDF（或 HTML），PDF 原样，图片原样。
    为什么不让浏览器直连：签名地址需要登录 Cookie，浏览器没有（我们本地服务
    与 courses.zju.edu.cn 不同源），直连会落到「下载」——这就是原来
    window.open 预览实际都变成下载的原因。
    """
    url = ('https://courses.zju.edu.cn/api/uploads/document/%s/url?preview=true'
           % upload_id)
    data = _get_json(url, timeout=30)
    u = (data or {}).get('url')
    if not (isinstance(u, str) and u.strip()):
        raise ValueError('该文件暂不支持在线预览，请下载查看')
    r = SESSION.request('GET', u.strip(), timeout=120)
    if r.status != 200:
        raise ValueError('预览服务返回 HTTP %s' % r.status)
    body = r.body or b''
    if len(body) > PREVIEW_MAX_BYTES:
        raise ValueError('预览文件超过 %dMB，请直接下载查看'
                         % (PREVIEW_MAX_BYTES // 1048576))
    ctype = SESSION._find_header(r.headers, 'Content-Type') \
        or 'application/octet-stream'
    return body, ctype



def submit_file_bytes(filename: str, data_bytes: bytes) -> int:
    """先把文件注册到学在浙大，拿到 upload_url 与 id，再 PUT 上传，返回文件 id。"""
    reg = _post_json('https://courses.zju.edu.cn/api/uploads', {
        'embed_material_type': '',
        'is_marked_attachment': False,
        'is_scorm': False,
        'is_wmpkg': False,
        'name': filename,
        'parent_id': 0,
        'parent_type': None,
        'size': len(data_bytes),
        'source': '',
    }, timeout=60)
    if reg.get('errors'):
        raise RuntimeError(f'上传注册失败: {reg["errors"]}')
    if not reg.get('id') or not reg.get('upload_url'):
        raise RuntimeError('上传注册失败：服务端未返回 upload_url（'
                           + json.dumps(reg, ensure_ascii=False)[:120] + '）')

    boundary = b'----zjucourseboundary'
    crlf = b'\r\n'
    body = (b'--' + boundary + crlf +
            b'Content-Disposition: form-data; name="file"; filename="' +
            filename.encode('utf-8') + b'"' + crlf +
            b'Content-Type: application/octet-stream' + crlf + crlf +
            data_bytes + crlf +
            b'--' + boundary + b'--' + crlf)

    # storage_type 为空/LOCAL → 直接 PUT 上传（与网页端 upload2Local 一致）；
    # S3 + WRPC 转码 → PUT 后还要回调确认。
    put_res = SESSION.request('PUT', reg['upload_url'], body=body, timeout=120,
                              headers={'Content-Type': 'multipart/form-data; boundary=' + boundary.decode(),
                                       'Accept': 'application/json'})
    if put_res.status >= 300:
        raise RuntimeError('文件上传失败：HTTP %s' % put_res.status)
    if reg.get('storage_type') == 'S3' and reg.get('transcoder') == 'WRPC':
        _post_json(f'https://courses.zju.edu.cn/internal-api/upload/callback/{reg["id"]}',
                   {'file_key': reg['id']}, timeout=60)
    return reg['id']


def submit_homework_activity(homework_id: int, file_ids, comment: str = '') -> bool:
    """
    把已上传的文件正式上交。file_ids 传列表即可一次上交多个附件
    （浙大接口 uploads 本来就是数组，单个 id 也兼容）。
    """
    url = f'https://courses.zju.edu.cn/api/course/activities/{homework_id}/submissions'

    payload = {
        'comment': f'<p>{comment}<br></p>' if comment else '',
        'is_draft': False,
        'mode': 'normal',
        'other_resources': [],
        'slides': [],
        'uploads': list(file_ids),
        'uploads_in_rich_text': [],
    }

    res = _post_json(url, payload, timeout=60)
    if res.get('errors'):
        raise RuntimeError('上交作业失败')
    invalidate_cache()
    return True


# ---------------------------------------------------------------- 本地服务 ----

TOKEN = secrets.token_urlsafe(32)
HANDLER_TEMPLATE_PLACEHOLDER = '__ZJUCOURSE_TOKEN__'
ALLOWED_HOSTS = {'127.0.0.1', 'localhost', '::1', '[::1]'}


def check_request(handler) -> bool:
    """
    安全校验：
      1) Host 必须来自本机（挡掉 DNS rebinding 之类的把戏）；
      2) 自定义头必须带上本次启动的随机 token（挡掉本机其它程序的偷偷访问）。
    """
    host = (handler.headers.get('Host') or '').split(':')[0].strip()
    if host not in ALLOWED_HOSTS:
        return False
    if handler.headers.get('X-Zjucourse-Token') != TOKEN:
        return False
    return True


class Handler(BaseHTTPRequestHandler):

    # 不在控制台打印访问日志
    def log_message(self, *args):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _html(self, text):
        body = text.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)

    def _stream_download(self, upload_id):
        """把学在浙大的文件一边读一边流式转给浏览器（含文件名）。"""
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        name = qs.get('name', [''])[0]
        try:
            resp = stream_upload(upload_id)
        except Exception as e:
            self._json({'ok': False, 'error': '下载失败：' + str(e)}, 502)
            return

        self.send_response(200)
        ctype = resp.headers.get('Content-Type') or 'application/octet-stream'
        self.send_header('Content-Type', ctype)
        cd = resp.headers.get('Content-Disposition')
        if not cd and name:
            try:
                cd = "attachment; filename*=UTF-8''" + urllib.parse.quote(name)
            except Exception:
                cd = 'attachment'
        if cd:
            self.send_header('Content-Disposition', cd)
        cl = resp.headers.get('Content-Length')
        if cl:
            self.send_header('Content-Length', cl)
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()

        try:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
        except Exception:
            pass
        finally:
            try:
                resp.close()
            except Exception:
                pass

    def _serve_static(self, path):
        """仅服务 libs/ 下的前端库文件（公开，不含用户数据）。防目录穿越。"""
        fname = path[len('/libs/'):]
        if not fname or '/' in fname or '\\' in fname or '..' in fname:
            self._json({'ok': False, 'error': '非法路径'}, 400)
            return
        fpath = os.path.join(RESOURCE_DIR, 'libs', fname)
        if not os.path.isfile(fpath):
            self._json({'ok': False, 'error': 'not found'}, 404)
            return
        ext = fname.rsplit('.', 1)[-1].lower()
        ct = {'js': 'application/javascript', 'css': 'text/css',
              'html': 'text/html'}.get(ext, 'application/octet-stream')
        try:
            data = open(fpath, 'rb').read()
        except Exception as e:
            self._json({'ok': False, 'error': str(e)}, 500)
            return
        self.send_response(200)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'public, max-age=3600')
        self.end_headers()
        self.wfile.write(data)

    def _api_preview_url(self, upload_id):
        """方案 B 预览：取学在浙大在线预览服务的签名 URL 返给前端（前端直开）。

        流程：GET https://courses.zju.edu.cn/api/uploads/document/{id}/url?preview=true
              → JSON {"url": "<签名预览地址>"}（浙大会把 doc/ppt/xls 转成 PDF/HTML、
                PDF 原样、图片原样）。前端拿到后 window.open 直连渲染，最稳最快。
        未登录/该文件不支持预览时，返回 ok=False，前端自动回退到下载。
        """
        url = 'https://courses.zju.edu.cn/api/uploads/document/%s/url?preview=true' % upload_id
        try:
            data = _get_json(url)

            if isinstance(data, dict):
                u = data.get('url')
                if isinstance(u, str) and u.strip():
                    self._json({'ok': True, 'url': u.strip()})
                    return
            self._json({'ok': False, 'error': '该文件暂不支持在线预览，请下载查看'}, 404)
        except Exception as e:
            self._json({'ok': False, 'error': '获取预览地址失败：' + str(e)}, 502)

    def _api_preview(self, upload_id):
        """内嵌预览：把学在浙大预览服务转好的内容原样转发给前端（前端用
        blob URL 在遮罩层里展示，图片 <img> / PDF·HTML <iframe>）。

        与 /api/preview_url 的区别：这里是**后端带登录会话**把内容拉下来，
        前端只认本地接口，不直接碰浙大域名——浏览器无需浙大 Cookie 也能
        真正渲染预览（而不是触发下载）。错误一律回 JSON，前端回退下载。
        """
        try:
            body, ctype = fetch_preview_bytes(upload_id)
        except ValueError as e:
            self._json({'ok': False, 'error': str(e)}, 404)
            return
        except Exception as e:
            self._json({'ok': False, 'error': '预览失败：' + str(e)}, 502)
            return
        self.send_response(200)
        self.send_header('Content-Type', ctype.split(';')[0].strip()
                         if ctype else 'application/octet-stream')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Content-Disposition', 'inline')
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        try:
            self.wfile.write(body)
        except Exception:
            pass

    def do_GET(self):
        path = self.path.split('?')[0]

        # 首页：注入本次启动的随机 token
        if path in ('/', '/index.html'):
            try:
                with open(os.path.join(RESOURCE_DIR, 'index.html'), 'r',
                          encoding='utf-8') as f:
                    html_text = f.read()
                self._html(html_text.replace(HANDLER_TEMPLATE_PLACEHOLDER, TOKEN))
            except FileNotFoundError:
                self._html('<h1>index.html 缺失，请确认和 server.py 在同一目录</h1>')
            return

        # 静态前端库（公开，不含用户数据）
        if path.startswith('/libs/'):
            self._serve_static(self.path.split('?')[0])
            return

        # 以下全部需要 token + Host 校验
        if not check_request(self):
            self._json({'ok': False, 'error': '未授权的访问'}, 403)
            return

        if path == '/api/status':
            self._json(api_status())
            return
        if path == '/api/semesters':
            self._json(api_semesters())
            return
        if path == '/api/courses':
            self._json(api_courses(force='force' in self.path))
            return
        if path == '/api/homework':
            self._json(api_homework(force='force' in self.path))
            return
        if path == '/api/courseware':
            qs = urllib.parse.parse_qs(self.path.split('?')[1]) if '?' in self.path else {}
            cid = qs.get('course_id', [''])[0]
            if not cid:
                self._json({'ok': False, 'error': '缺少 course_id'}, 400)
                return
            self._json(api_courseware(cid))
            return
        if path == '/api/course-homework':
            qs = urllib.parse.parse_qs(self.path.split('?')[1]) if '?' in self.path else {}
            cid = qs.get('course_id', [''])[0]
            if not cid:
                self._json({'ok': False, 'error': '缺少 course_id'}, 400)
                return
            self._json(api_course_homework(cid))
            return
        if path == '/api/course-lives':
            qs = urllib.parse.parse_qs(self.path.split('?')[1]) if '?' in self.path else {}
            cid = qs.get('course_id', [''])[0]
            if not cid:
                self._json({'ok': False, 'error': '缺少 course_id'}, 400)
                return
            self._json(api_course_lives(cid))
            return
        if path.startswith('/api/download/'):
            uid = path[len('/api/download/'):].split('?')[0]
            self._stream_download(uid)
            return
        if path == '/api/download_dir':
            self._json({'ok': True, 'dir': get_download_dir()})
            return
        if path.startswith('/api/preview_url/'):
            uid = path[len('/api/preview_url/'):].split('?')[0]
            self._api_preview_url(uid)
            return
        if path.startswith('/api/preview/'):
            uid = path[len('/api/preview/'):].split('?')[0]
            self._api_preview(uid)
            return
        if path == '/api/grades':
            qs = urllib.parse.parse_qs(self.path.split('?')[1]) if '?' in self.path else {}
            self._json(api_grades(force='force' in qs))
            return

        self._json({'ok': False, 'error': 'not found'}, 404)

    def do_POST(self):
        length = int(self.headers.get('Content-Length') or 0)
        raw = self.rfile.read(length) if length else b''
        try:
            payload = json.loads(raw.decode('utf-8')) if raw else {}
        except Exception:
            payload = {}

        path = self.path.split('?')[0]
        if not check_request(self):
            self._json({'ok': False, 'error': '未授权的访问'}, 403)
            return

        if path == '/api/login':
            self._json(api_login(payload))
            return
        if path == '/api/logout':
            self._json(api_logout())
            return
        if path == '/api/submit':
            self._json(api_submit(payload))
            return
        if path == '/api/download_dir':
            ok = set_download_dir(payload.get('dir'))
            self._json({'ok': ok, 'dir': get_download_dir(),
                        'error': None if ok else '文件夹不存在，设置未生效'})
            return
        if path == '/api/pick_dir':
            self._json(_pick_dir_via_child())
            return
        if path.startswith('/api/save_download/'):
            uid = path[len('/api/save_download/'):].split('?')[0]
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            self._json(api_save_download(uid, qs.get('name', [''])[0],
                                         qs.get('course', [''])[0]))
            return
        if path == '/api/open_download_dir':
            self._json(api_open_download_dir())
            return
        if path == '/api/lives/export_ppt':
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            sub_id = qs.get('sub_id', [''])[0]
            if not sub_id:
                self._json({'ok': False, 'error': '缺少 sub_id'}, 400)
                return
            try:
                self._json(export_live_ppt(
                    sub_id, qs.get('url', [''])[0],
                    course=qs.get('course', [''])[0],
                    fallback_name=qs.get('name', [''])[0]))
            except Exception as e:
                self._json({'ok': False, 'error': '导出失败：' + str(e)}, 200)
            return

        self._json({'ok': False, 'error': 'not found'}, 404)


# ---------------------------------------------------------------- 成绩查询 ----
# 成绩来自浙大教务系统 ETA（正方老接口，CAS 会话直连，无需额外登录）。
# 均绩计算采用 Celechron 的口径：
#   · 按学分加权的五分制均绩（ETA 直接给出每门课的绩点 JD）；
#   · 按学年 + 长学期分组，最后附「全部」汇总；
#   · 排除：弃修(BZ) / 未出分(CJ 为空) / 二级制合格·不合格(只计学分不计绩点) /
#     英语水平测试（按二级制处理：只计学分不计绩点）/
#     二三四课堂（按课程名识别，学分绩点都不计）。
ETA_HOME_URL = 'http://eta.zju.edu.cn/index/student'
ETA_GRADE_LIST_URL = 'http://eta.zju.edu.cn/zftal-xgxt-web/api/teacher/xshx/getKccjList.zf'
GRADE_CACHE_KEY = 'grades_eta_v2'

# 等级制成绩 → 百分制换算（百分制 GPA 与挂科判定都要用）
_GRADE_LETTER_TO_SCORE = {
    'A+': 95, 'A': 90, 'A-': 87, 'B+': 83, 'B': 80, 'B-': 77,
    'C+': 73, 'C': 70, 'C-': 67, 'D': 60, 'F': 0,
    '优秀': 90, '良好': 80, '中等': 70, '及格': 60, '不及格': 0,
    '合格': 75, '不合格': 0, '弃修': 0, '缺考': 0, '缓考': 0, '待录': 0, '无效': 0,
}
# 五分制绩点 → 4.3 满分四分制绩点（浙大成绩单换算规则）
_FIVE_TO_FOUR = {5.0: 4.3, 4.8: 4.2, 4.5: 4.1, 4.2: 4.0}
# 这些「原始成绩」不计入 GPA / 学分
_EXCLUDE_GPA = ('弃修', '待录', '缓考', '无效', '合格', '不合格')
_EXCLUDE_CREDIT = ('弃修', '待录', '缓考', '无效')


def _json_of_eta(body: bytes):
    """教务接口返回的 JSON 可能是 UTF-8 也可能是 GBK，先严格试再兜底。"""
    if not body:
        return None
    text = None
    for enc in ('utf-8', 'gbk'):
        try:
            text = body.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        text = body.decode('utf-8', 'replace')
    try:
        return json.loads(text)
    except Exception:
        return None


def _to_float(v):
    try:
        return 0.0 if v is None else float(str(v).strip())
    except Exception:
        return 0.0


def _semester_group(xq: str) -> str:
    """ETA 的季度（春/夏/短/秋/冬）归并成长学期。"""
    xq = (xq or '').strip()
    if xq in ('春', '夏', '春夏', '2'):
        return '春夏'
    if xq in ('秋', '冬', '秋冬', '短', '1'):
        return '秋冬'
    return '未知'


def _hundred_score(cj: str) -> float:
    """等级制成绩换算百分制；数字成绩直接取数字部分。"""
    if cj in _GRADE_LETTER_TO_SCORE:
        return float(_GRADE_LETTER_TO_SCORE[cj])
    m = re.search(r'\d+(?:\.\d+)?', cj)
    return float(m.group(0)) if m else 0.0


def _four_point_gpa(jd: float) -> float:
    """五分制绩点 → 4.3 满分四分制；超过 4.0 但不在换算表里的按 4.0 封顶。"""
    if jd in _FIVE_TO_FOUR:
        return _FIVE_TO_FOUR[jd]
    return jd if jd <= 4.0 else 4.0


def _grade_row(name, cj, credit, jd, xn, xq):
    """
    把一条成绩记录整理成统一结构，并打上两个参与计算的标记：
      creditIncluded — 计入学分（弃修/待录/缓考/无效不计）
      gpaIncluded    — 计入绩点（在计学分基础上再排除二级制、
                       英语水平测试与二三四课堂）
    """
    cj = str(cj or '').strip()
    name = str(name or '').strip()
    if not name or not cj:
        return None
    # 二三四课堂（课程名形如「第二课堂」「三课堂」等）：学分、绩点都不计
    is_kt = bool(re.search(r'第?[二三四]\s*课堂', name))
    # 英语水平测试是合格/不合格科目：只计学分不计绩点（无论 ETA 里 CJ 显示成什么）
    is_pf = '英语水平测试' in name
    credit_included = cj not in _EXCLUDE_CREDIT and not is_kt
    gpa_included = (credit_included and cj not in ('合格', '不合格')
                    and not is_kt and not is_pf)
    return {
        'name': name,
        'grade': cj,
        'credit': credit,
        'gpa': jd,                                   # 五分制绩点
        'gpa4': _four_point_gpa(jd),                 # 4.3 满分四分制
        'score': _hundred_score(cj),                 # 百分制换算
        'xn': str(xn or '').strip(),
        'xq': str(xq or '').strip(),
        'creditIncluded': credit_included,
        'gpaIncluded': gpa_included,
        # 获得学分：计学分且绩点不为 0（挂科不给学分）
        'earned': credit if (credit_included and jd != 0) else 0.0,
    }


def _rows_from_eta(items):
    """解析 ETA 老接口的 items（字段是大写的 KCMC/CJ/XF/JD/XN/XQ/BZ）。"""
    rows = []
    for g in items:
        try:
            if not isinstance(g, dict):
                continue
            if str(g.get('BZ') or '').strip() == '弃修':
                continue
            cj = g.get('CJ')
            if cj is None or str(cj).strip() == '':
                continue
            row = _grade_row(g.get('KCMC'), cj, _to_float(g.get('XF')),
                             _to_float(g.get('JD')), g.get('XN'),
                             _semester_group(g.get('XQ')))
            if row:
                rows.append(row)
        except Exception:
            continue
    return rows


def _semester_order_key(xn: str, xq: str):
    """学年新在前；同学年里春夏(2)比秋冬(1)大，倒序后新学期排前面。"""
    return (xn or '', '2' if xq == '春夏' else '1')


def _gpa_stats(rows):
    """一组成绩的四种口径加权绩点 + 学分统计（只统计 gpaIncluded 的课程）。"""
    earned = round(sum(r['earned'] for r in rows), 1)
    inc = [r for r in rows if r['gpaIncluded']]
    tc = sum(r['credit'] for r in inc)
    if tc <= 0:
        return {'gpa': 0.0, 'gpa4': 0.0, 'gpa100': 0.0,
                'credit': 0.0, 'earnedCredit': earned}
    return {
        'gpa': round(sum(r['gpa'] * r['credit'] for r in inc) / tc, 2),
        'gpa4': round(sum(r['gpa4'] * r['credit'] for r in inc) / tc, 2),
        'gpa100': round(sum(r['score'] * r['credit'] for r in inc) / tc, 1),
        'credit': round(tc, 1),
        'earnedCredit': earned,
    }


def _build_payload(rows, source):
    """按学期分组 → 每学期统计 + 全部汇总，成绩条目新学期在前。
    统计组只收录还有计学分课程的学期（全是弃修/缓考的学期不出卡）。"""
    rows = [r for r in rows if r['xn']]
    rows.sort(key=lambda r: (_semester_order_key(r['xn'], r['xq']),
                             r['name']), reverse=True)
    groups, order = {}, []
    for r in rows:
        if not r['creditIncluded']:
            continue
        k = (r['xn'], r['xq'])
        if k not in groups:
            groups[k] = []
            order.append(k)
        groups[k].append(r)
    analysis = []
    for k in order:
        st = _gpa_stats(groups[k])
        st.update({'xn': k[0], 'xq': k[1]})
        analysis.append(st)
    total = _gpa_stats(rows)
    total.update({'xn': '全部', 'xq': '汇总'})
    return {'grades': rows, 'analysis': analysis, 'total': total,
            'source': source}


def fetch_grades():
    """
    从 ETA 拉全部课程成绩（200 条封顶，足够覆盖本科所有课程）。
    ETA 的 Cookie 没种好 / 过期时，先访问一次 ETA 首页把 CAS 票换好再试。
    """
    if not CURRENT_STUID:
        raise RuntimeError('还没记住学号：请退出登录后重新登录一次（成绩查询需要学号）')
    url = ETA_GRADE_LIST_URL + '?' + urllib.parse.urlencode({
        'xh': CURRENT_STUID,
        'currentPage': '1', 'showCount': '200',
        'xn': '', 'xq': '', 'kcmc': '',
        'orders': '[]', 'sfjg': '',
    })

    def _try_fetch():
        try:
            body = SESSION.request('GET', url, timeout=45).body
            data = _json_of_eta(body) or {}
            items = (data.get('data') or {}).get('items')
            if isinstance(items, list):
                return items
        except Exception:
            pass
        return None

    eta_items = _try_fetch()
    if eta_items is None:
        try:
            SESSION.request('GET', ETA_HOME_URL, timeout=25)
        except Exception:
            pass
        eta_items = _try_fetch()
    if eta_items is None:
        raise RuntimeError('成绩接口无响应（可能登录已过期），请退出后重新登录再试')

    return _build_payload(_rows_from_eta(eta_items), 'eta')


def api_grades(force=False):
    try:
        data = cached(GRADE_CACHE_KEY, 300, fetch_grades, force=force)
        return {'ok': True, 'grades': data['grades'],
                'analysis': data['analysis'], 'total': data.get('total'),
                'source': data.get('source')}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def api_login(payload):
    stuid = (payload.get('stuid') or '').strip()
    password = payload.get('password') or ''
    if not stuid or not password:
        return {'ok': False, 'error': '请输入学号和密码'}
    try:
        ok = do_login(stuid, password)
    except Exception as e:
        del password
        return {'ok': False, 'error': f'登录请求失败：{e}'}
    del password
    if ok:
        invalidate_cache()
        return {'ok': True}
    return {'ok': False, 'error': '学号或密码错误，或网络异常'}


def api_logout():
    global CURRENT_STUID
    CURRENT_STUID = ''
    COOKIE_JAR.clear()
    invalidate_cache()
    clear_session()
    return {'ok': True}


def api_status():
    return {'ok': True, 'logged_in': is_logged_in()}


def api_semesters():
    try:
        return {'ok': True, 'semesters': get_semesters()}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def api_courses(force=False):
    try:
        return {'ok': True, 'courses': get_courses(force=force)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def api_homework(force=False):
    try:
        courses = get_courses(force=force)
        return {'ok': True,
                'homeworks': get_all_homework(courses, only_active=False)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def api_courseware(course_id):
    try:
        cid = int(course_id)
    except Exception:
        return {'ok': False, 'error': 'course_id 无效'}
    try:
        data = get_courseware(cid)
        return {'ok': True, 'chapters': data['chapters'], 'courseware': data['activities']}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def api_course_homework(course_id):
    try:
        cid = int(course_id)
    except Exception:
        return {'ok': False, 'error': 'course_id 无效'}
    try:
        course_name = ''
        try:
            for c in get_courses():
                if c['id'] == cid:
                    course_name = c['name']
                    break
        except Exception:
            pass
        return {'ok': True, 'course_name': course_name,
                'homeworks': get_course_homework(cid, course_name)}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def api_submit(payload):
    """
    提交作业。支持两种形式：
      · 新版多文件：{'homework_id': id, 'files': [{'filename':.., 'b64':..}, ...]}
      · 旧版单文件：{'homework_id': id, 'filename':.., 'b64':..}（向后兼容）
    流程：逐个把文件注册并上传到学在浙大拿到文件 id，然后一次性
    作为一次提交（uploads 数组）上交，返回实际上交的文件名列表。
    """
    try:
        homework_id = int(payload['homework_id'])
        comment = payload.get('comment', '')
        files = payload.get('files') or []
        if not files and payload.get('filename') and payload.get('b64'):
            files = [{'filename': payload['filename'], 'b64': payload['b64']}]
        if not files:
            return {'ok': False, 'error': '没有要提交的文件'}
        file_ids = []
        names = []
        for f in files:
            data = base64.b64decode(f['b64'])
            file_ids.append(submit_file_bytes(f['filename'], data))
            names.append(f['filename'])
        submit_homework_activity(homework_id, file_ids, comment)
        return {'ok': True, 'files': names}
    except Exception as e:
        return {'ok': False, 'error': str(e)}


def _free_port(port):
    """
    释放占用指定端口的进程（仅 Windows，且只杀本机用户自己的进程）。

    为什么要做这个：以前端口被旧 server 占着时，新进程会静默换一个随机端口，
    导致你浏览器里那个固定地址（127.0.0.1:8733）一直指向「旧代码」，
    新加的接口全部 404。现在改成「占用就先释放、再绑回固定端口」，
    重启服务后访问的固定地址一定是新鲜代码。
    """
    if sys.platform != 'win32':
        return
    try:
        proc = subprocess.run(['netstat', '-ano'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        out = proc.stdout.decode('gbk', errors='ignore')
        for line in out.splitlines():
            if (':%d ' % port) not in line or 'LISTENING' not in line:
                continue
            pid = line.split()[-1]
            subprocess.run(['taskkill', '/F', '/PID', pid],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
    except Exception:
        return


def pick_port(preferred=PREFERRED_PORT, allow_random=True):
    """优先用首选端口 8733；若被占用，先释放占用进程再重试固定端口。
    仍失败才退回到随机端口（极端情况才走到这里）。

    allow_random=False 时（如 Tauri 显式指定端口）：绑定失败直接抛 OSError，
    不再偷偷换端口——否则桌面外壳会连到错误端口。
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        try:
            s.bind((HOST, preferred))
            port = preferred
        except OSError:
            if not allow_random:
                raise
            _free_port(preferred)
            bound = False
            for _ in range(3):
                try:
                    s.bind((HOST, preferred))
                    port = preferred
                    bound = True
                    break
                except OSError:
                    time.sleep(0.3)
            if not bound:
                s.bind((HOST, 0))
                port = s.getsockname()[1]
    finally:
        s.close()
    return port


def start_server():
    """启动本地服务（非阻塞），返回实际占用的端口。供打包后的 exe 调用。"""
    port = pick_port()
    httpd = ThreadingHTTPServer((HOST, port), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return port


def main():
    import argparse
    ap = argparse.ArgumentParser(description='ZJU-Course 本地服务')
    ap.add_argument('--tauri', action='store_true',
                    help='Tauri 桌面端模式：不开浏览器，并打印 ZJUCOURSE_PORT 供外壳读取')
    ap.add_argument('--no-browser', action='store_true', help='不自动打开系统浏览器')
    ap.add_argument('--port', type=int, default=None, help='固定监听端口（冲突即报错）')
    args = ap.parse_args()

    preferred = args.port or PREFERRED_PORT
    if args.port is not None:
        allow_random = False
    else:
        allow_random = True
    open_browser = not (args.no_browser or args.tauri)

    port = pick_port(preferred, allow_random=allow_random)
    url = f'http://{HOST}:{port}/'

    if args.tauri:
        print(f'ZJUCOURSE_PORT={port}', flush=True)
        safe_print('  [Tauri 模式] 端口已由桌面外壳加载，无需浏览器')
    else:
        safe_print('========================================================')
        safe_print('  ZJU-Course 已启动')
        safe_print(f'  请用浏览器打开: {url}')
        safe_print(f'  会话加密保存在: {SESSION_FILE}')
        safe_print('  关闭本窗口即可退出程序')
        safe_print('========================================================')

    if open_browser:
        try:
            import webbrowser
            webbrowser.open(url)
        except Exception:
            pass

    try:
        ThreadingHTTPServer((HOST, port), Handler).serve_forever()
    except KeyboardInterrupt:
        safe_print('\n已退出')
    finally:
        SESSION.close()


if __name__ == '__main__':
    # 子进程模式：只弹一次原生选文件夹窗口，把结果写进指定文件后退出
    if '--pick-dir-child' in sys.argv:
        out_path = sys.argv[sys.argv.index('--pick-dir-child') + 1]
        try:
            r = pick_folder_native()
        except Exception:
            import traceback
            r = {'ok': False,
                 'error': '选择窗口异常：' + traceback.format_exc(limit=3)}
        try:
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(r, f, ensure_ascii=False)
        except Exception:
            pass
    else:
        main()
