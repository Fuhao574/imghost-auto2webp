<?php

declare(strict_types=1);

/**
 * lib.php — 图床公共部分：配置、鉴权、路径安全、GD 转码
 *
 * 设计取舍：
 *  - 鉴权用「HMAC 签名 cookie」而不是 session。这台主机的 open_basedir 里虽然有
 *    /php_sessions，但 session 会把状态放在服务端，多一个依赖就多一个不确定因素。
 *    签名 cookie 无状态、口令改了立刻全失效、也不怕 session 目录不可写。
 *  - 所有文件操作都走 safeJoin()，用 realpath 前缀校验锁死在 images/ 内，
 *    杜绝 ../ 穿越。删除是唯一破坏性操作，额外再校验一次扩展名。
 *  - 命名沿用博客现有约定：一篇博文一个文件夹，文件夹名 = post slug（保留大小写，
 *    因为 how-to-choose-SHP 这种带大写的真实存在），封面 = <slug>-cover.<ext>。
 */

/**
 * 口令哈希与 cookie 签名密钥**不再有内置默认值**。
 *
 * 以前这里是写死的一个出厂口令哈希，任何人拿到这份代码都能登进用同一份代码
 * 部署的站 —— 公开仓库等于公开口令。现在首次部署时现生成一个随机口令，
 * 写进 secret.php，并**强制改掉才能继续用**。
 *
 * 想彻底重置：删掉 secret.php，下次访问会重新生成一个。
 * 明文口令任何时候都不该出现在源码里，只留 bcrypt 哈希。
 */
/**
 * 首次部署生成的口令长度（字符）。
 *
 * 20 个字符、字母表 56 位，约 116 bit 熵 —— 比我能想得到的任何人口令都强。
 * 关键是**随机**：以前出厂口令写死在代码里，仓库一公开就等于所有人都知道，
 * fork 一份部署就能直接登进别人的站。
 */
const INIT_PW_LEN = 20;

const COOKIE_NAME = 'ih';

/**
 * 登录 cookie 有效期。
 *
 * 无状态 cookie 的固有性质：登出只能让浏览器删掉 cookie，服务端没有吊销名单，
 * 所以被抄走的 cookie 值在过期前仍能重放（实测过，改一个字节才会失效）。
 * 唯一的补救手段是「改口令」—— 那会轮换 hmac，一次性作废所有旧 cookie。
 *
 * 30 天太长，压到 7 天。个人图床每天至少开一次，7 天不影响使用，
 * 但万一泄露，暴露窗口只有一周而不是一个月。
 */
const COOKIE_TTL  = 60 * 60 * 24 * 7;

/** 封面模式固定参数，与 Blog.tsx 的约定绑定，不开放调节 */
const COVER_W      = 1672;
const COVER_Q      = 88;
const COVER_THUMB  = 320;
const COVER_THUMB_Q = 80;

/**
 * 正文内嵌图的固定参数（界面上不再提供「最大宽」输入框）。
 *
 * 【为什么质量固定在 82】
 * 正文图的实际内容是 DNS 面板、测速结果这类**小字截图**，
 * 按理说有损压缩最容易在文字边缘出彩边。实测（q-pipeline.php / q-decision.php）
 * 结论相反：q80~q92 全部 ≥44 dB PSNR，肉眼并排看**分不出区别**，
 * 而 q82→q92 要多付 30% 体积。所以 82 够用，再往上是纯浪费。
 *
 * 【为什么宽度是 2560】
 * 站点的正文容器**没有 max-width**，图文列宽 = 视口宽 - 522（Layout.tsx 的 DualLayout），
 * 加上根元素 zoom（dpr=1 时 1.5 倍，index.html 注入），实际需要的图像宽度是：
 *
 *   1920 屏 dpr=1   → 正文 758 CSS px  → 需 1137 设备像素   2560 有余量
 *   2560 屏 dpr=1   → 正文 1185 CSS px → 需 1777 设备像素   2560 有余量
 *   1920 屏 dpr=2   → 正文 1398 CSS px → 需 2796 设备像素   2560 基本 1:1
 *   3840 屏 dpr=2   → 正文 3318 CSS px → 需 6636 设备像素   不够（只能靠 srcset 阶梯）
 *
 * 现有源图是 2660~2874 宽，缩到 2560 只剩 0.89~0.96 倍 —— 文字的「软」主要是
 * 缩放这一步造成的，**不是 WebP 的 q**。实测 q82→q92 肉眼分不出区别（PSNR 都 ≥44 dB），
 * 想让文字清楚该动的是宽度不是质量。
 *
 * 之前是 1920，代价是「1920 屏 dpr=2」（15" MBP、2K 显示器，很常见）会把图
 * 放大 1.46 倍。改成 2560 覆盖这个场景，体积涨约 40%（实测 82 KB → 111 KB @q82）。
 * 反正不足不会放大，宽度只影响「大图会不会被缩」这一件事。
 */
const NORMAL_MAX_W = 2560;
const NORMAL_Q     = 82;

const MAX_FILES = 12;

const ROOT     = __DIR__;
const IMAGES   = ROOT . '/images';
const THEME_CSS = ROOT . '/theme.css';

/**
 * 口令哈希 + cookie 签名密钥的存放位置。
 *
 * 放在 private/secret.php 而不是直接改 lib.php，有两个好处：
 *   1. 改口令时只写这一个小文件，写坏了 lib.php 依然能跑，图床不会被搞挂。
 *   2. 文件里有「只在被直接访问时才退出」的守卫，别人敲 /private/secret.php
 *      只会拿到空白输出，hash 不会泄露。
 *
 * 注意守卫不能用 `<?php exit; ?>` —— secret() 是用 include 读的，
 * 那句 exit 会把整个请求直接终止掉（曾经踩过：请求静默返回空响应）。
 */
const SECRET_DIR  = ROOT . '/private';
const SECRET_FILE = SECRET_DIR . '/secret.php';

/**
 * 初始口令明文暂存的文件。改完口令立刻删掉。
 *
 * 放在 SECRET_DIR 定义之后是必须的：PHP 的文件级 const 按顺序求值，
 * 写在前面就成了「Undefined constant」致命错误 —— 而且这个错只在**运行**
 * 时报，php -l 照样说语法没问题。
 */
const INIT_PW_FILE = SECRET_DIR . '/initial-password.txt';

/**
 * 墓碑文件：记下「曾经发布过、后来被删掉或改名让出」的每个**完整文件名**和它的内容指纹。
 *
 * 为什么非有不可 —— 版本号机制（-v2 / -v3）**只在文件还在的时候生效**。
 * resolveVersion() 一看「这个名字空着」就直接拿去用。可名字被回收过一次之后：
 *
 *     传 A   →  x-cover.webp        ← 这个 URL 已经被浏览器 / CDN 缓存了
 *     删掉   →  磁盘上没了，但地址还留在别人缓存里
 *     传 B   →  又叫 x-cover.webp   ← URL 没变，内容换了
 *
 * 于是「删了重传」看到的还是旧图，**图库和博客页面一起中招**（同一个 <img src>）。
 * 墓碑把用过的文件名**烧掉**：再占用同一个名字、内容又不同，就必须升版本号。
 *
 * 存 sha 是为了保住「同一张图重传不换 URL」这条性质 —— 只记「烧过」的话，
 * 删掉再传同一张图会平白多出一个 -v2，CDN 缓存全白打散。
 *
 * 按**完整文件名**存（而不是「目录 + 名字 + 版本号」三段拆开记）：文件名本身
 * 可能合法地以 -v2 结尾（有人传 `my-v2.png`），拆开记就会把它误认成
 * `my` 的第 2 版，键对不上，墓碑等于白记。
 *
 * 放 private/ 而不是 images/：images/ 是对外可访问的目录，这份数据没理由公开。
 */
const TOMBSTONE_FILE = SECRET_DIR . '/tombstones.json';

/** 最多记多少个文件名。超了丢最旧的（PHP 的关联数组保持插入序）。
 *  这个数只是防跑偏，不是配额 —— 正常一个博客几百张图，离上限远得很。 */
const TOMBSTONE_MAX_NAMES = 400;

/**
 * 站名与头像，跟主站对齐 —— 登录页要复刻 LoginCard 的「头像 + 标题」版式。
 * 头像用主站同一个 GitHub 头像 URL，不额外传文件。
 */
const SITE_NAME     = 'Fuhao574';
const SITE_TAGLINE  = '这个世界不缺大人';
const SITE_FAVICON  = 'https://avatars.githubusercontent.com/u/220566987?v=4&s=100';

/**
 * 浏览器标签页标题。
 *
 * 之前这里用的是主站的标题（Fuhao574-这个世界不缺大人），那是在图床跟主站
 * 共用一个 host 时代定的。现在这是个独立域名，独立申请了证书，标签页里
 * 再显示主站的名字既认不出是哪个站、也点不过去 —— 改成「图床 - Fuhao574」，
 * 一眼就知道开的是哪个。
 *
 * 只管标签页。界面上的产品名是 SITE_PRODUCT，下面那个常量，两个别搞混。
 */
const SITE_TITLE    = '图床 - Fuhao574';

/** 界面上的产品名 */
const SITE_PRODUCT  = 'Fuhao574的图床';

/** 允许落盘的扩展名 —— 同时也是「可删除」的判定依据 */
const ALLOWED_EXT = ['webp', 'jpg', 'jpeg', 'png', 'gif', 'avif'];

/**
 * 动图原样保存时的体积上限。
 *
 * 动图是唯一一类「不能转码」的上传 —— 别的都能压小，动图压了就丢帧。
 * 于是它也是唯一一类**体积由用户说了算**的上传：普通图出来是 WebP，
 * 最多几十 KB；动图原样落盘，一个 3 MB 的 GIF 就是 3 MB，之后每次浏览
 * 都在花这个钱。5 MB 是「一张动图不至于离谱」和「别把主机流量吃掉」之间
 * 随手划的线。
 */
const ANIM_MAX_BYTES = 5 * 1024 * 1024;

function boot(): void
{
    @ini_set('memory_limit', '256M');
    @ini_set('display_errors', '0');   // 不要把报错吐给访客
    error_reporting(E_ALL);
    @set_error_handler(static function (int $no, string $msg, string $file, int $line): bool {
        error_log("[imghost] $msg ($file:$line)");
        return true;
    });
}

// ============================================================
// 工具
// ============================================================

function b64u(string $raw): string
{
    return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
}

function b64u_dec(string $s): string
{
    return base64_decode(strtr($s, '-_', '+/'), true) ?: '';
}

function fmtBytes(int $b): string
{
    if ($b >= 1048576) {
        return round($b / 1048576, 2) . ' MB';
    }
    if ($b >= 1024) {
        return round($b / 1024) . ' KB';
    }
    return $b . ' B';
}

/** 极简 ini 体积解析：把 "8M"/"2048K" 变成字节数；0 或负数返回 null（无限制） */
function iniBytes(string $key): ?int
{
    $raw = trim((string) @ini_get($key));
    if ($raw === '' || !preg_match('/^(-?\d+)\s*([KMG])?B?$/i', $raw, $m)) {
        return null;
    }
    $n = (int) $m[1];
    return $n <= 0 ? null : $n * match (strtoupper($m[2] ?? '')) {
        'G'     => 1073741824,
        'M'     => 1048576,
        'K'     => 1024,
        default => 1,
    };
}

function iniHuman(string $key): string
{
    $raw = trim((string) @ini_get($key));
    $b   = iniBytes($key);
    if ($b === null) {
        return $raw . ' (无限制)';
    }
    return $raw . ' (' . ($b >= 1048576 ? round($b / 1048576, 2) . ' MB' : round($b / 1024) . ' KB') . ')';
}

// ============================================================
// 鉴权
// ============================================================

/** 校验口令，成功返回签名 cookie 的值。$hmac 允许传入新密钥（改口令后重新签发用）。 */
function makeAuthCookie(string $password, ?string $hmac = null): ?string
{
    if (!password_verify($password, secret()['hash'])) {
        return null;
    }
    $exp  = time() + COOKIE_TTL;
    $body = b64u(json_encode(['exp' => $exp], JSON_THROW_ON_ERROR));
    $sig  = hash_hmac('sha256', $body . '|' . $exp, $hmac ?? secret()['hmac']);
    return $body . '.' . $sig;
}

function authed(): bool
{
    $raw = (string) ($_COOKIE[COOKIE_NAME] ?? '');
    if (!str_contains($raw, '.')) {
        return false;
    }
    [$body, $sig] = explode('.', $raw, 2);
    $payload = json_decode(b64u_dec($body), true);
    if (!is_array($payload) || !isset($payload['exp'])) {
        return false;
    }
    $exp = (int) $payload['exp'];
    if ($exp < time()) {
        return false;
    }
    $want = hash_hmac('sha256', $body . '|' . $exp, secret()['hmac']);
    // 双保险：签名对不上直接拒，时间戳也要落在签名覆盖范围内
    return hash_equals($want, $sig) && $exp - COOKIE_TTL <= time();
}

function sendAuthCookie(?string $value): void
{
    // secure 标志只在 HTTPS 下发，否则明文 HTTP 访问时浏览器会直接丢弃 cookie
    $https = ($_SERVER['HTTPS'] ?? '') !== '' && strtolower((string) $_SERVER['HTTPS']) !== 'off';
    $base  = [
        'path'     => '/',
        'secure'   => $https,
        'httponly' => true,
        'samesite' => 'Lax',
    ];
    if ($value === null) {
        setcookie(COOKIE_NAME, '', $base + ['expires' => time() - 3600]);
        return;
    }
    setcookie(COOKIE_NAME, $value, $base + ['expires' => time() + COOKIE_TTL]);
}

/**
 * CSRF token：由签名 cookie 派生，无需额外存储。
 *
 * $cookieValue 传的是 cookie 的**纯值**（就是 $_COOKIE[COOKIE_NAME] 的内容），
 * 不带 "name=" 前缀 —— 带了就和下面的默认分支算出两个不同的 token，
 * 症状是「改口令成功，但紧接着每个写操作都 403」。
 *
 * 什么时候需要显式传：改口令时。此时 hmac 已经轮换、cookie 也刚签发，
 * 但 $_COOKIE 里还是请求带来的旧值，而浏览器此刻手上已经是新 cookie 了。
 * 所以必须用新值算，否则前端换不到匹配的 token。
 */
function csrfToken(?string $cookieValue = null): string
{
    $raw = $cookieValue ?? (string) ($_COOKIE[COOKIE_NAME] ?? '');
    return substr(hash_hmac('sha256', 'csrf|' . $raw, secret()['hmac']), 0, 32);
}

function checkCsrf(): bool
{
    $sent = (string) ($_POST['csrf'] ?? $_SERVER['HTTP_X_CSRF'] ?? '');
    return $sent !== '' && hash_equals(csrfToken(), $sent);
}

function jsonOut(array $data, int $code = 200): never
{
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Robots-Tag: noindex, nofollow');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    exit;
}

// ============================================================
// 口令与密钥
// ============================================================

/**
 * 读取当前生效的口令哈希与签名密钥。
 *
 * secret.php 不存在 = 首次部署 → 现生成一个随机口令，写进 secret.php，
 * 并置 mustChange，此后不改成自己的口令就一直不能用（见 mustChangeSecret()）。
 *
 * secret.php 损坏（语法错 / 不是数组 / 字段缺失）也按「重新生成」处理。
 * 以前这里是退回内置默认口令的 —— 现在没有默认口令了，退无可退，
 * 而「重新生成一个并显示出来」正好是这种情况下唯一能让人进得去的路。
 * 旧的坏文件会被新的覆盖掉。
 *
 * 返回值：
 *   fromFile    用的 secret.php 里的值
 *   broken      原来那个文件坏了（已重新生成）
 *   generated   这一次是现生成的（明文在 initialPassword() 里）
 *   mustChange  当前口令还是生成的那个，必须改掉才能继续用
 */
/** secret() 的请求内缓存。放全局是因为函数 static 缓存没法从外部重置。 */
$GLOBALS['__secret'] = null;

function secret(): array
{
    if ($GLOBALS['__secret'] !== null) {
        return $GLOBALS['__secret'];
    }

    if (is_file(SECRET_FILE)) {
        // 关键：先做结构校验，通过了才 include。
        // PHP 的「语法错误」是 fatal error，@include 压不住 —— 文件一旦被写坏，
        // 直接 include 会让整个请求 500，图床就这么锁死了（曾经真的踩到）。
        // 所以这里先按字符串看一眼形状，不合格就压根不去执行它。
        $raw = @file_get_contents(SECRET_FILE);
        $shapeOk = is_string($raw)
            && str_starts_with($raw, "<?php")
            && preg_match("/'hash'\\s*=>\\s*'\\\$2y\\\$12\\\$[\\/.A-Za-z0-9]{53}'/", $raw) === 1
            && preg_match("/'hmac'\\s*=>\\s*'[0-9a-f]{64}'/", $raw) === 1;

        if ($shapeOk) {
            $r = @include SECRET_FILE;
            if (is_array($r) && !empty($r['hash']) && !empty($r['hmac'])) {
                return $GLOBALS['__secret'] = [
                    'hash'       => (string) $r['hash'],
                    'hmac'       => (string) $r['hmac'],
                    // 老版本写出的文件没有这个键。那说明主人在这台主机上
                    // 已经主动设过口令了，不该因为升级再逼他改一遍 ——
                    // 缺失按「不用改」处理。
                    'mustChange' => !empty($r['mustChange']),
                    'fromFile'   => true,
                    'broken'     => false,
                    'generated'  => false,
                ];
            }
            error_log('[imghost] secret.php 形状对但没返回 hash/hmac，重新生成');
        } else {
            error_log('[imghost] secret.php 内容不符合预期（可能被写坏或截断），未执行它，重新生成');
        }
        return $GLOBALS['__secret'] = generateInitialSecret(true);
    }

    return $GLOBALS['__secret'] = generateInitialSecret(false);
}

/**
 * 生成一份全新的口令 + 签名密钥，写进 secret.php，并置 mustChange。
 *
 * $broken 只影响返回值上的标记，界面上用来区别「首次部署」和
 * 「原来的文件坏了，重新来过」。
 *
 * 明文不写进 secret.php（那儿只有 bcrypt 哈希），而是单独放一个
 * initial-password.txt —— 改完口令立刻删掉。留这一份是因为
 * 「只在生成那一次请求里显示一次」不够：谁都有刷新错、关错标签页的时候，
 * 没有备份就等于把自己锁在外面了。
 */
function generateInitialSecret(bool $broken): array
{
    $pw = generatePassword();
    $hash = password_hash($pw, PASSWORD_BCRYPT, ['cost' => 12]);
    if (!is_string($hash) || !str_starts_with($hash, '$2y$')) {
        // 生成不了哈希就只能死等：没有口令就没人能进来，包括来修它的人
        throw new RuntimeException('生成 bcrypt 哈希失败，图床无法完成首次初始化');
    }
    $hmac = bin2hex(random_bytes(32));

    if (!saveSecret($hash, $hmac, true)) {
        error_log('[imghost] 初始 secret.php 写不出去，请检查 private/ 的权限');
    } else {
        // 明文单独存一份。用 ASCII，且只含字母数字，编码风险最小。
        @file_put_contents(
            INIT_PW_FILE,
            "Initial password of the image host.\n"
            . "Change it in the UI, then this file is deleted automatically.\n"
            . "If you lost it: delete private/secret.php and reload, a new one is generated.\n\n"
            . $pw . "\n"
        );
        @chmod(INIT_PW_FILE, 0600);
    }
    $GLOBALS['__initPw'] = $pw;

    return [
        'hash'       => $hash,
        'hmac'       => $hmac,
        'mustChange' => true,
        'fromFile'   => true,
        'broken'     => $broken,
        'generated'  => true,
    ];
}

/**
 * 随机口令。
 *
 * 字母表去掉了 0 O 1 l I —— 这几个字符在小写字体和很多终端里长得一模一样，
 * 而这个口令是要让人**手打进去**的。少几个字符不心疼，看错一个才心疼。
 * 不带符号也是同一个理由：省掉复制粘贴时的转义麻烦。
 */
function generatePassword(int $len = INIT_PW_LEN): string
{
    $alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    $n = strlen($alphabet);
    if ($n < 2) {
        throw new RuntimeException('字母表坏了');
    }
    $max = $n - 1;
    $out = '';
    for ($i = 0; $i < $len; $i++) {
        // 用 random_int 而不是 random_bytes 取模 —— 后者有模偏，
        // 字母表大小 56 不是 2 的幂，分布会偏，头几个字符更容易被猜到
        $out .= $alphabet[random_int(0, $max)];
    }
    return $out;
}

/**
 * 初始口令明文。只在「本次请求刚生成出来」或者
 * 「INIT_PW_FILE 还在（也就是还没改口令）」时拿得到。
 */
function initialPassword(): ?string
{
    if (isset($GLOBALS['__initPw'])) {
        return (string) $GLOBALS['__initPw'];
    }
    if (!is_file(INIT_PW_FILE)) {
        return null;
    }
    $raw = @file_get_contents(INIT_PW_FILE);
    if (!is_string($raw)) {
        return null;
    }
    $lines = preg_split('/\R/', trim($raw)) ?: [];
    $pw = trim((string) end($lines));
    return $pw === '' ? null : $pw;
}

/** 改完口令就把明文那份删掉，不留残余 */
function forgetInitialPassword(): void
{
    $GLOBALS['__initPw'] = null;
    if (is_file(INIT_PW_FILE)) {
        @unlink(INIT_PW_FILE);
    }
}

/** 改口令后立刻让当前请求用上新值，否则同一请求里签发的 cookie 会带旧密钥 */
function secretSet(array $s): void
{
    $GLOBALS['__secret'] = $s + ['fromFile' => true, 'broken' => false, 'generated' => false];
}

/**
 * 口令检查。
 *
 * 只保留两条硬性约束，其余（长度、字符种类）一律不管 —— 这是个人图床，
 * 口令强度该由自己判断，规则太多反而烦。
 *
 *   1. 两次输入一致
 *   2. 不超过 72 字节
 *
 * 第 2 条不是强度要求，是 bcrypt 的硬限制：它只取输入的前 72 字节。
 * 静默截断会让人误以为口令更长更安全，实际上多出来的部分根本不参与验证。
 * 所以这里明确报错，而不是假装接受了。72 字节约等于 24 个汉字，够用了。
 */
const BCRYPT_MAX_BYTES = 72;

function checkNewPassword(string $pw, string $confirm): ?string
{
    if ($pw !== $confirm) {
        return '两次输入不一致';
    }
    if ($pw === '' || trim($pw) === '') {
        return '口令不能为空';
    }
    $len = strlen($pw);
    if ($len > BCRYPT_MAX_BYTES) {
        return '口令 ' . $len . ' 字节，超过 bcrypt 的 ' . BCRYPT_MAX_BYTES
             . ' 字节上限（多出来的部分不会被验证，等于白写）';
    }
    return null;
}

/** 界面上展示用的相对路径，例如 private/secret.php */
function secretPath(): string
{
    return 'private/' . basename(SECRET_FILE);
}

// ============================================================
// 登录爆破防护
// ============================================================
//
// 原来只有一句 sleep(2)：慢是慢了，但没有任何计数，攻击者并行开 20 条连接
// 就是每秒 20 次猜测，慢的那一下等于没有。对一个口令保护的工具来说这是硬伤，
// 因为口令是唯一的屏障。
//
// 现在的策略是三层，从便宜到贵：
//   1. 递增等待    前几次失败按 2/4/8/16/30 秒递增。持着 PHP worker 干等，
//                  本身就是成本 —— 免费主机的 worker 数量有限。
//   2. 硬锁定      窗口内失败够多次就锁一段时间。锁定期间**根本不跑 bcrypt**，
//                  所以「锁定期间口令是对的」也照样被拒，不泄露任何信息。
//   3. 记录跨请求   计数写在 private/login-guard.json，靠文件而不是 MySQL ——
//                  和这个项目别的地方一致：单口令、无并发冲突，一个小 JSON 足够。
//
// 已知的局限，明说：按 IP 计数挡不住有肉鸡的分布式攻击，也挡不住同一 IP
// 换口令硬啃。对个人图床来说，配合一条不含常见词的口令，这个量级够用了。

/** 计数窗口：只记得住这段时间内的失败 */
const GUARD_WINDOW = 900;
/** 窗口内失败多少次开始硬锁 */
const GUARD_MAX_FAILS = 10;
/** 硬锁持续多久（秒） */
const GUARD_LOCK_SECS = 900;
/**
 * 递增等待表，最后一档是封顶。累加到第 10 次要花 150 多秒，够让脚本觉得不划算。
 */
const GUARD_BACKOFF = [2, 5, 10, 15, 20];
/**
 * 给 bcrypt + 输出 + 收尾留的余量（秒）。
 *
 * 这条是被一个真实的 500 逼出来的：sleep() 是算在 max_execution_time 里的，
 * 睡过头整个请求会被 PHP 直接掐掉。症状特别难认 ——
 *   - 返回 HTTP 500，而不是干净的 401 / 429
 *   - 失败记录来不及写，计数永远停在触发等待的那一档
 *   - 500 和 401 的差别本身就是个指纹，等于告诉攻击者「你进到慢路径了」
 *
 * 本地 max_execution_time=30 配上 30 秒 backoff，第五次失败直接 500。
 * 线上是 60 秒、不会立刻炸，但余量太薄，所以按预算封顶，不赌。
 */
const GUARD_TIME_RESERVE = 10;

/**
 * 已经失败 fails 次的话，下一次尝试要等多久。
 *
 * 单独抽出来是因为 guardStatus() 和 guardFail() 都要算这个值。
 * 之前两处各写一遍 GUARD_BACKOFF[min($fails, ...)]，差了一档：
 * 客户端被告知「下次等 2 秒」，实际等的是 4 秒。
 */
function guardWaitFor(int $fails): int
{
    if ($fails <= 0) {
        return 0;   // 还没失败过，第一次不等 —— 不浪费正常用户的时间
    }
    return GUARD_BACKOFF[min($fails - 1, count(GUARD_BACKOFF) - 1)];
}

/**
 * 这次请求实际能睡多久 —— 在 backoff 表和执行时间预算之间取小的。
 * 见 GUARD_TIME_RESERVE 的说明。
 */
function guardSleepBudget(): int
{
    $top   = GUARD_BACKOFF[count(GUARD_BACKOFF) - 1];
    $limit = (int) ini_get('max_execution_time');
    if ($limit <= 0) {
        return $top;   // 没设上限（CLI 或无限），就用表里的最大值
    }
    return max(0, min($top, $limit - GUARD_TIME_RESERVE));
}

/**
 * 取客户端 IP。
 *
 * 站点在 Cloudflare 后面，REMOTE_ADDR 拿到的是 Cloudflare 边缘节点的 IP ——
 * 拿它计数的话，全世界所有访客会共用一个计数器，一个 IP 输错就把所有人锁了。
 * CF-Connecting-IP 才是真实来源。
 *
 * 之所以敢直接信这个头：图床是你自己的域名，走 Cloudflare 访问时 CF 会
 * **覆盖**客户端送来的同名头，所以伪造不了。前提是这站只能经 Cloudflare 到达
 * （DNS 指向 CF、源站不开给公网直连）；如果不满足，攻击者自己加这个头就能绕开。
 */
function clientIp(): string
{
    $cf = (string) ($_SERVER['HTTP_CF_CONNECTING_IP'] ?? '');
    // 只认合法 IPv4/IPv6 字符，长度也卡一下 —— 免得塞进来一长串垃圾把 JSON 撑大
    if ($cf !== '' && strlen($cf) <= 45 && filter_var($cf, FILTER_VALIDATE_IP)) {
        return $cf;
    }
    $ra = (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    return $ra !== '' ? substr($ra, 0, 45) : '0.0.0.0';
}

/**
 * 记录里用的键。不存明文 IP —— 免得这个文件变成一份「谁在撞我的门」的名单。
 * 用 hmac 当盐，就算有人拿到文件也回推不出原 IP。
 */
function guardKey(): string
{
    return substr(hash_hmac('sha256', 'login|' . clientIp(), secret()['hmac']), 0, 32);
}

function guardPath(): string
{
    return SECRET_DIR . '/login-guard.json';
}

/**
 * 读记录，顺手做两件事：
 *   - 丢掉窗口外的条目（不然文件只增不减）
 *   - 丢掉形状不对的条目（手改坏 / 并发写坏）
 *
 * 读不出来一律当成空记录：宁可暂时没有计数，也不要因为一个坏 JSON
 * 把所有人都锁在门外。
 */
function guardRead(): array
{
    $p = guardPath();
    if (!is_file($p)) {
        return [];
    }
    $raw = @file_get_contents($p);
    if (!is_string($raw) || $raw === '' || strlen($raw) > 262144) {
        return [];
    }
    $d = json_decode($raw, true);
    if (!is_array($d)) {
        error_log('[imghost] login-guard.json 解析失败，当作空记录处理');
        return [];
    }
    $now  = time();
    $keep = [];
    foreach ($d as $k => $v) {
        if (!is_string($k) || !is_array($v)) {
            continue;
        }
        $lockedUntil = is_int($v['l'] ?? null) ? (int) $v['l'] : 0;
        $fails = [];
        foreach (($v['f'] ?? []) as $ts) {
            if (is_int($ts) && $ts > $now - GUARD_WINDOW) {
                $fails[] = $ts;
            }
        }

        // 只在「确实锁过、而且锁期已过」时才把整条丢掉。
        //
        // 判断条件里的 $lockedUntil > 0 不能省：还没锁过的记录 l 就是 0，
        // 而 0 <= time() 恒成立 —— 少了这个判断，每条记录都会被丢掉，
        // 失败次数永远停在 1，递增等待和锁定全都失效（而且不报错，只是静默）。
        if ($lockedUntil > 0 && $lockedUntil <= $now) {
            // 锁服完了，失败记录一并清掉。
            //
            // 不清的话会出现一个很难解释的情况：锁 900 秒、失败窗口也 900 秒，
            // 两者几乎同时产生，但失败记录会残留到最后几条。用户熬完 15 分钟，
            // 以为能重新开始，结果只剩一两次机会就又被锁上。
            //
            // 锁本身就是惩罚，服完了就该给一个干净的起点。
            continue;
        }

        if ($fails === [] && $lockedUntil <= $now) {
            continue;   // 没锁、也没有窗口内的失败，没什么要记的
        }
        $keep[$k] = ['f' => $fails, 'l' => max(0, $lockedUntil)];
    }
    return $keep;
}

/** 原子写。用临时文件 + rename，避免并发读到半截 JSON。 */
function guardWrite(array $d): bool
{
    if (!ensurePrivateDir()) {
        return false;
    }
    $body = json_encode($d, JSON_UNESCAPED_SLASHES);
    if (!is_string($body)) {
        return false;
    }
    $tmp = guardPath() . '.' . bin2hex(random_bytes(4)) . '.tmp';
    $n   = @file_put_contents($tmp, $body, LOCK_EX);
    if ($n !== strlen($body)) {
        @unlink($tmp);
        return false;
    }
    if (!@rename($tmp, guardPath())) {
        @unlink($tmp);
        return false;
    }
    @chmod(guardPath(), 0600);
    return true;
}

/**
 * 取当前状态。返回：
 *   locked      是不是正锁着
 *   retryAfter  还剩多少秒解锁
 *   fails       窗口内已失败次数
 *   left        距离触发锁定还差几次
 *   backoff     「再错一次要等几秒」—— 没锁定时才有意义
 */
function guardStatus(): array
{
    $key = guardKey();
    $d   = guardRead();
    $e   = $d[$key] ?? ['f' => [], 'l' => 0];
    $now = time();

    $locked = ($e['l'] ?? 0) > $now;
    $fails  = count($e['f'] ?? []);

    return [
        'locked'     => $locked,
        'retryAfter' => $locked ? (int) $e['l'] - $now : 0,
        'fails'      => $fails,
        'left'       => max(0, GUARD_MAX_FAILS - $fails),
        'backoff'    => guardWaitFor($fails),
    ];
}

/**
 * 记一次失败，返回记完之后的状态。
 *
 * 触发锁定的判断放在「已经失败够多次之后」，也就是第 GUARD_MAX_FAILS 次
 * 失败当场锁定 —— 不多不少，正好是用户直觉里的「试满 N 次就锁」。
 */
function guardFail(): array
{
    $key = guardKey();
    $d   = guardRead();
    $now = time();

    $e = $d[$key] ?? ['f' => [], 'l' => 0];
    $e['f'][] = $now;
    // 只保留窗口内的
    $e['f'] = array_values(array_filter(
        $e['f'],
        static fn(int $ts): bool => $ts > $now - GUARD_WINDOW
    ));
    if (count($e['f']) >= GUARD_MAX_FAILS) {
        $e['l'] = $now + GUARD_LOCK_SECS;
    }
    $d[$key] = $e;

    // 别人已经过期掉的条目顺手清掉，文件不会只增不减
    foreach ($d as $k => $v) {
        if ($k === $key) {
            continue;
        }
        $lk = is_int($v['l'] ?? null) ? (int) $v['l'] : 0;
        if (($v['f'] ?? []) === [] && $lk <= $now) {
            unset($d[$k]);
        }
    }

    guardWrite($d);

    $fails  = count($e['f']);
    $locked = $e['l'] > $now;
    return [
        'locked'     => $locked,
        'retryAfter' => $locked ? $e['l'] - $now : 0,
        'fails'      => $fails,
        'left'       => max(0, GUARD_MAX_FAILS - $fails),
        'backoff'    => guardWaitFor($fails),
    ];
}

/** 登录成功：把这个 IP 的记录清掉。不能留着累积次数影响下次登录。 */
function guardReset(): void
{
    $key = guardKey();
    $d   = guardRead();
    if (!isset($d[$key])) {
        return;
    }
    unset($d[$key]);
    guardWrite($d);
}

/**
 * 确保 private/ 存在、可写，并带上一份拒绝直接访问的 .htaccess。
 *
 * secret.php 和登录爆破记录都住在这儿，所以单独抽出来 ——
 * 之前只有 saveSecret() 里面顺手建，导致「还没改过口令、private/ 还不存在」的
 * 新站上，登录防护第一次想写记录会失败（静默退化成没有防护）。
 */
function ensurePrivateDir(): bool
{
    if (!is_dir(SECRET_DIR) && !@mkdir(SECRET_DIR, 0700, true) && !is_dir(SECRET_DIR)) {
        return false;
    }
    if (!is_writable(SECRET_DIR)) {
        return false;
    }
    // 双保险：万一主机的 AllowOverride 关了、PHP 守卫也被人绕过了，
    // 至少 Apache 这层还挡着。
    $htaccess = SECRET_DIR . '/.htaccess';
    if (!is_file($htaccess)) {
        // 同样只用 ASCII：这份 .htaccess 万一写坏，Apache 可能整站 500。
        @file_put_contents($htaccess,
            "# Private directory of the image host -- deny all direct access.\n"
            . "<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n"
            . "<IfModule !mod_authz_core.c>\n    Order deny,allow\n    Deny from all\n</IfModule>\n");
    }
    return true;
}

/**
 * 原子写 secret.php：先写临时文件再 rename。
 * 中途断电或并发写入只会留下一个临时文件，不会把 secret.php 写成半截。
 *
 * $mustChange 会写进文件。true = 这是首次生成的那个口令，主人在界面里
 * 改过之后才变 false。secret() 读不到这个键时按 false 处理（见那里的注释）。
 */
function saveSecret(string $hash, string $hmac, bool $mustChange = false): bool
{
    if (!ensurePrivateDir()) {
        return false;
    }

    // 生成的注释刻意只用 ASCII。这个文件一旦解析失败，secret() 会重新生成
    // 一份（等于把主人换了个口令），所以能少一个编码风险就少一个。
    $body = "<?php\n"
          . "/**\n"
          . " * Private data for the image host. Written automatically by the\n"
          . " * \"change password\" form -- do not edit by hand.\n"
          . " *\n"
          . " * Guard: exit only when this file is the ENTRY script (i.e. someone\n"
          . " * typing /private/secret.php in a browser). When it is included,\n"
          . " * SCRIPT_FILENAME points at index.php, the condition is false, and we\n"
          . " * return normally.\n"
          . " *\n"
          . " * Do NOT use `<?php exit; ?>` here: that exit would terminate the entire\n"
          . " * request that includes this file, and the host would silently return\n"
          . " * an empty response.\n"
          . " *\n"
          . " * hash = bcrypt(password, cost 12). The plaintext is never stored here.\n"
          . " * hmac = HMAC key for the login cookie. Rotated on every password change,\n"
          . " *        which invalidates sessions on all other devices.\n"
          . " * mustChange = true while the password is still the generated one; the\n"
          . " *        UI refuses every write until the owner changes it.\n"
          . " */\n"
          . "\$_entry = (string) (\$_SERVER['SCRIPT_FILENAME'] ?? '');\n"
          . "if (\$_entry === '' || realpath(\$_entry) === realpath(__FILE__)) {\n"
          . "    exit;   // direct access: output nothing\n"
          . "}\n"
          . "unset(\$_entry);\n"
          . "\n"
          . 'return ' . var_export(
              ['hash' => $hash, 'hmac' => $hmac, 'mustChange' => $mustChange],
              true
          ) . ";\n";

    $tmp = SECRET_FILE . '.' . bin2hex(random_bytes(4)) . '.tmp';
    $n   = @file_put_contents($tmp, $body, LOCK_EX);
    if ($n !== strlen($body)) {
        @unlink($tmp);
        return false;
    }
    if (!@rename($tmp, SECRET_FILE)) {
        @unlink($tmp);
        return false;
    }
    @chmod(SECRET_FILE, 0600);
    return true;
}

// ============================================================
// 路径安全
// ============================================================

/**
 * 文件夹名规整。保留大小写（how-to-choose-SHP 是真实存在的），
 * 只允许字母数字、点、下划线、连字符，禁止 . .. 与前导点。
 */
function sanitizeFolder(string $raw): string
{
    $s = trim($raw);
    // 先把路径分隔符当普通字符换成连字符，别让 a/../../b 拼出带 .. 的名字
    $s = str_replace(['/', '\\'], '-', $s);
    $s = preg_replace('/[^A-Za-z0-9._-]+/', '-', $s) ?? '';
    $s = preg_replace('/-{2,}/', '-', $s) ?? '';
    $s = trim($s, '-');
    // 残留的 . 只可能来自「.」「..」「...」，一律拒掉而不是留着
    if ($s === '' || preg_match('/^\.+$/', $s) || str_contains($s, '..')) {
        return '';
    }
    if (!preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]*$/', $s)) {
        return '';
    }
    return substr($s, 0, 64);
}

/** 文件名规整（不含扩展名部分） */
function sanitizeStem(string $raw): string
{
    $s = trim($raw);
    $s = preg_replace('/[^A-Za-z0-9._-]+/', '-', $s) ?? '';
    $s = preg_replace('/-{2,}/', '-', $s) ?? '';
    $s = trim($s, '-');
    if ($s === '' || $s === '.' || $s === '..') {
        return '';
    }
    return substr($s, 0, 80);
}

/**
 * 归一化路径分隔符后再比较。
 * realpath() 在 Windows 返回反斜杠、拼接时用的是正斜杠，直接 str_starts_with
 * 会静默失配 —— 表现为「目录明明存在却说不存在」。统一成正斜杠、去掉尾斜杠。
 */
function normPath(string $p): string
{
    return rtrim(str_replace('\\', '/', $p), '/');
}

/**
 * 解析一个文件夹的绝对路径，不做创建。
 * sanitizeFolder 已经把 / 和 . .. 全剥掉了，所以拼接在文本上就不会逃出 base；
 * 目录已存在时再用 realpath 复核一次，挡住软链。
 */
function resolveFolder(string $folder): ?string
{
    $base = realpath(IMAGES);
    if ($base === false) {
        return null;
    }
    $folder = sanitizeFolder($folder);
    if ($folder === '') {
        return null;
    }
    $dir  = $base . '/' . $folder;
    $baseN = normPath($base);
    if (!str_starts_with(normPath($dir), $baseN . '/')) {
        return null;
    }
    if (is_dir($dir)) {
        $real = realpath($dir);
        if ($real === false || !str_starts_with(normPath($real), $baseN . '/')) {
            return null;
        }
        return $real;
    }
    return $dir;
}

/**
 * images/ 根目录下的某个文件。sanitizeFolder('') 会返回空串，所以不能走 safeJoin，
 * 这里单独处理。返回 null 表示不在 images/ 内。
 */
function safeJoinRoot(string $name): ?string
{
    $base = realpath(IMAGES);
    if ($base === false) {
        return null;
    }
    $name = basename(str_replace('\\', '/', $name));
    if ($name === '' || $name === '.' || $name === '..' || str_starts_with($name, '.')) {
        return null;
    }
    $full = $base . '/' . $name;
    if (is_file($full)) {
        $real = realpath($full);
        if ($real === false || !str_starts_with(normPath($real), normPath($base) . '/')) {
            return null;
        }
        return $real;
    }
    return str_contains(normPath($full), '/../') ? null : $full;
}

function ensureFolder(string $folder): ?string
{
    $dir = resolveFolder($folder);
    if ($dir === null) {
        return null;
    }
    if (is_dir($dir)) {
        return $dir;
    }
    return @mkdir($dir, 0755, true) || is_dir($dir) ? $dir : null;
}

/**
 * 重命名一个文件或文件夹。
 *
 * 文件夹重命名比文件危险：图库里的 URL、博客 frontmatter 里写死的 image: 全都指向
 * 旧路径。所以文件夹重命名时必须把「有哪些地方会因此失效」讲清楚，并且默认不动。
 * 而 Cloudflare 按 URL 键缓存，旧 URL 还会继续返回旧图 —— 这不是删得掉的东西。
 *
 * $isFolder 决定用哪套校验。
 */
function renameEntry(string $relPath, string $newName, bool $isFolder): array
{
    $relPath = trim($relPath);

    if ($isFolder) {
        $oldName = sanitizeFolder($relPath);
        $newName = sanitizeFolder($newName);
    } else {
        // 文件名里带路径分隔符一律拒掉。
        // 不能靠 basename() 收拾 —— basename('a/b') 会安静地返回 'b'，
        // 用户以为改的是 b，实际把他想表达的东西丢掉了。宁可报错让他重填。
        if (str_contains($newName, '/') || str_contains($newName, '\\')) {
            throw new RuntimeException('文件名里不能带路径分隔符（/ 或 \\），只写名字本身');
        }
        // 同理，relPath 是接口给的路径，本来就该是 folder/file 或纯 file，
        // 如果带了 ../ 说明调用方有问题，直接报出来而不是让 basename 悄悄兜住。
        if (str_contains($relPath, '..')) {
            throw new RuntimeException('路径不合法');
        }
        $oldName = basename(str_replace('\\', '/', $relPath));
        // 用户可能带扩展名（"a.webp"），也可能不带（"a"）。两种都归一成不带扩展名的 stem，
        // 否则会拼出 orig.webp.renamed.webp 这种鬼名字。
        //
        // 不能用 pathinfo($s, PATHINFO_EXTENSION) 判断：点可以出现在名字中间
        // （"my.post-2026"），pathinfo 会把 "post-2026" 误认成扩展名。
        // 规则改成：只有结尾确实是已知扩展名之一，才把它剥掉。
        $stemInput = basename(str_replace('\\', '/', trim($newName)));
        $tail      = strrchr($stemInput, '.');
        if ($tail !== false && in_array(strtolower(substr($tail, 1)), ALLOWED_EXT, true)) {
            $stemInput = substr($stemInput, 0, -strlen($tail));
        }
        $newName = sanitizeStem($stemInput);
    }

    if ($oldName === '') {
        throw new RuntimeException('原名称不合法');
    }
    if ($newName === '') {
        throw new RuntimeException('新名称里没有可用字符（只允许字母、数字、点、下划线、连字符）');
    }
    if (strcasecmp($oldName, $newName) === 0) {
        throw new RuntimeException('新名字和原来一样');
    }

    if ($isFolder) {
        $from = resolveFolder($oldName);
        $to   = resolveFolder($newName);
        if ($from === null || !is_dir($from)) {
            throw new RuntimeException('文件夹不存在');
        }
        if (is_dir((string) $to)) {
            throw new RuntimeException('已经有一个叫 ' . $newName . ' 的文件夹了');
        }
        if (!@rename($from, (string) $to)) {
            throw new RuntimeException('改名失败，检查 images/ 是否可写');
        }
        return [
            'kind' => 'folder',
            'from' => $oldName,
            'to'   => $newName,
            // 相对 images/ 的路径，前端拿它跟图库里的 path 对齐。
            // 只回 to（纯文件夹名）的话，前端还得自己拼，猜错了就是「改名后没选中」。
            'path' => $newName,
        ];
    }

    // 文件。$relPath 可能是 "folder/file.webp"（上传都在子文件夹里），
    // 也可能只是 "file.webp"（根目录）。两种都要处理。
    $ext = strtolower(pathinfo($oldName, PATHINFO_EXTENSION));
    if (!in_array($ext, ALLOWED_EXT, true)) {
        throw new RuntimeException('只能重命名这些格式：' . implode('、', ALLOWED_EXT));
    }

    $rel = str_replace('\\', '/', $relPath);
    $dir = dirname($rel);
    $inRoot = ($dir === '.' || $dir === '' || $dir === '/');
    $from = $inRoot ? safeJoinRoot($oldName) : safeJoin($dir, $oldName);

    if ($from === null || !is_file($from)) {
        throw new RuntimeException('文件不存在（或不在 images/ 内）');
    }

    // 目标 = 同一个目录 + 新名字 + 原扩展名。
    // 注意不能用 $from . '.' . $newName —— $from 是含原文件名的完整路径，
    // 那样会拼出 orig.webp.renamed.webp 这种鬼名字。
    $targetDir = dirname($from);
    $target    = $targetDir . '/' . $newName . '.' . $ext;

    if (is_file($target)) {
        throw new RuntimeException('已经有一个叫 ' . basename($target) . ' 的文件了');
    }
    if (!@rename($from, $target)) {
        throw new RuntimeException('改名失败，检查 images/ 是否可写');
    }
    $newBase = basename($target);
    return [
        'kind' => 'file',
        'from' => $oldName,
        'to'   => $newBase,
        'path' => $inRoot ? $newBase : $dir . '/' . $newBase,
    ];
}

/**
 * 拼一个确定落在 images/ 内的文件路径。
 * 文件夹部分交给 resolveFolder 校验；文件名只取 basename，客户端传来的 ../ 被这一刀砍掉；
 * 文件已存在时再用 realpath 复核一次真实位置，挡住软链。
 */
function safeJoin(string $folder, string $name): ?string
{
    $dir = resolveFolder($folder);
    if ($dir === null) {
        return null;
    }
    $name = basename(str_replace('\\', '/', $name));
    if ($name === '' || $name === '.' || $name === '..') {
        return null;
    }
    $full = $dir . '/' . $name;
    if (str_contains(normPath($full), '/../')) {
        return null;
    }
    if (is_file($full)) {
        $base = realpath(IMAGES);
        $real = realpath($full);
        if ($base === false || $real === false || !str_starts_with(normPath($real), normPath($base) . '/')) {
            return null;
        }
        return $real;
    }
    return $full;
}

// ============================================================
// 图库扫描
// ============================================================

/**
 * 递归列出 images/ 下所有图片，按文件夹分组。
 * 跳过点文件（.htaccess 等）与 .tmp- 残留。
 *
 * 空文件夹也会列出来（count = 0）—— 「新建文件夹」之后立刻就该在左侧树里看到它，
 * 否则那个文件夹等于凭空消失了，用户会以为没建成功。
 */
function scanImages(): array
{
    $base = realpath(IMAGES);
    if ($base === false) {
        return [];
    }
    $groups = [];

    // 先把所有子目录登记一遍（含空的）
    $dirs = @scandir($base) ?: [];
    sort($dirs, SORT_NATURAL | SORT_FLAG_CASE);
    foreach ($dirs as $d) {
        if ($d === '.' || $d === '..' || str_starts_with($d, '.')) {
            continue;
        }
        if (!is_dir($base . '/' . $d)) {
            continue;
        }
        $groups[$d] = [
            'folder' => $d,
            'slug'   => $d,
            'files'  => [],
            'bytes'  => 0,
            'count'  => 0,
            'cover'  => null,
            'mtime'  => (int) @filemtime($base . '/' . $d),
            'isRoot' => false,
        ];
    }

    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );

    foreach ($it as $info) {
        /** @var SplFileInfo $info */
        if (!$info->isFile()) {
            continue;
        }
        $path = $info->getPathname();
        if (str_starts_with($info->getFilename(), '.') || str_starts_with($info->getFilename(), '.tmp-')) {
            continue;
        }
        $ext = strtolower($info->getExtension());
        if (!in_array($ext, ALLOWED_EXT, true)) {
            continue;
        }
        // 统一用正斜杠。Windows 上 realpath 给的是反斜杠，不归一的话
        // path 会带着 \ 进 JSON，前端再拿它拼 URL 就成了 .../jwt-login\jwt-login-cover.webp
        $rel  = normPath(substr($path, strlen($base) + 1));
        $dir  = dirname($rel);
        $dir  = $dir === '.' ? '' : normPath($dir);
        $size = (int) $info->getSize();

        $groups[$dir] ??= [
            'folder'  => $dir === '' ? '(根目录)' : $dir,
            'slug'    => $dir,
            'files'   => [],
            'bytes'   => 0,
            'count'   => 0,
            'cover'   => null,   // 该文件夹里的封面（<slug>-cover.*）
            'mtime'   => 0,      // 文件夹内最新的 mtime，排序用
            'isRoot'  => $dir === '',
        ];
        $mtime = (int) $info->getMTime();
        $item  = [
            'path'  => $rel,
            'name'  => $info->getFilename(),
            'ext'   => $ext,
            'bytes' => $size,
            'mtime' => $mtime,
            'url'   => imgUrl($rel),
            'dir'   => $dir,
        ];
        $groups[$dir]['files'][] = $item;
        $groups[$dir]['bytes']  += $size;
        $groups[$dir]['count']  += 1;
        $groups[$dir]['mtime']   = max($groups[$dir]['mtime'], $mtime);
    }

    /**
     * 文件夹封面：<slug>-cover.<ext>，或它的版本 <slug>-cover-v2.<ext>。
     *
     * 取**版本号最大的那个**，不是「无后缀的那个」。
     *
     * 原来这里是无后缀精确匹配，于是踩了个很难自查的坑：删掉重传之后，
     * 正确的那张可能叫 x-cover-v2.webp，而传错那张 x-cover.webp 还躺在原地
     * —— 按名字匹配会挑中**旧的**，症状就是「明明传对了，图库封面还是错的」。
     *
     * 原来的模糊兜底（str_startswith '<slug>-cover.'）也救不了：
     * 'x-cover-v2.webp' 并不以 'x-cover.' 开头。
     *
     * 版本组只允许 -v + 数字，所以 x-cover-320.webp 那张缩略图混不进来
     * （它的 -320 不是版本号）。
     */
    foreach ($groups as $dir => &$g) {
        if ($dir === '') {
            continue;
        }
        $re   = '/^' . preg_quote($g['slug'] . '-cover', '/') . '(?:-v(\d+))?\.[A-Za-z0-9]+$/';
        $best = 0;
        foreach ($g['files'] as $f) {
            if (!preg_match($re, $f['name'], $m)) {
                continue;
            }
            $v = (($m[1] ?? '') === '') ? 1 : (int) $m[1];
            if ($v > $best) {
                $best      = $v;
                $g['cover'] = $f;
            }
        }
    }
    unset($g);

    uksort($groups, static fn(string $a, string $b): int => strnatcasecmp($a, $b));
    foreach ($groups as &$g) {
        usort($g['files'], static fn(array $a, array $b): int => strnatcasecmp($a['name'], $b['name']));
    }
    unset($g);

    return array_values($groups);
}

/**
 * 图床对外域名。
 *
 * 不能直接用 $_SERVER['HTTP_HOST'] —— 那会让「谁访问就拼谁的 host」：
 * 用 IP 或带端口访问时，会把 http://1.2.3.4:8080/images/... 这种临时地址
 * 写进图库数据和复制框，之后再从正常域名访问就看到坏链。
 * 锁死成固定域名，两边行为一致。
 */
const PUBLIC_HOST = 'img.fuhao574.cyou';

function imgUrl(string $relPath): string
{
    return 'https://' . PUBLIC_HOST . '/images/'
        . implode('/', array_map('rawurlencode', explode('/', $relPath)));
}

// 「哪个文件是封面」由 scanImages() 直接算好放进 $group['cover']（含整个文件对象），
// 不再单独提供 findCover()。之前是两套判断：scanImages 用严格相等匹配
// （<slug>-cover.<ext>），findCover 用前缀匹配，规则不一样会各标各的。

// ====================================
// 动图识别
// ====================================
//
// 为什么必须提前判：GD 的 imagecreatefromgif / imagecreatefromwebp
// **只解第一帧**。动图走正常流程的话，转出来的 WebP 是静的 ——
// 动画没了，而且用户根本看不出来（图还在显示，只是不动）。
// 静默丢数据比报错糟糕得多，所以要在 loadImage() 之前拦下来。
//
// 只认三种容器。往下的分支都是按各自的文件格式规范走块结构，
// 没有一个靠「猜」：
//
//   GIF    逐块走一遍，数 Image Descriptor（0x2C）出现几次
//   WebP   RIFF 里有 ANIM 块（VP8X 的 flags 位 1 也必然置上，但那块是
//          在文件里可能出现也可能不出现的，ANIM 才是动图必有物）
//   PNG    acTL 块出现在 IDAT 之前 —— 这是 APNG 的定义
//
// 动图 AVIF 没做。那要解 ISOBMFF 的 moov/trak 盒子体系，
// 动静与否藏在 trak 的 stsd 里；而动图 AVIF 在「博客配图」这种
// 场景里基本见不到，见不到的东西硬写一套解析器不值得 ——
// 真传进来会被当静态图处理，动画丢失（跟现在一样）。

/**
 * 这个文件是不是动图。
 *
 * 判错的方向很重要：
 *   误判「不是」 → 走了转码，动画被静默丢掉（bad）
 *   误判「是」   → 原样保存一张静态图，文件可能大一点（可接受）
 * 所以拿不准的时候一律往「是」偏。
 */
function isAnimated(string $path): bool
{
    if (!is_file($path) || !is_readable($path)) {
        return false;
    }
    $fh = @fopen($path, 'rb');
    if ($fh === false) {
        return false;
    }
    try {
        $head = (string) fread($fh, 64);
        if (strlen($head) >= 6) {
            $sig = substr($head, 0, 6);
            if ($sig === 'GIF87a' || $sig === 'GIF89a') {
                return gifIsAnimated($fh, $head);
            }
            if (substr($head, 0, 4) === 'RIFF' && substr($head, 8, 4) === 'WEBP') {
                return webpIsAnimated($fh);
            }
            if (substr($head, 0, 8) === "\x89PNG\r\n\x1a\n") {
                return pngIsAnimated($fh);
            }
        }
        return false;
    } finally {
        fclose($fh);
    }
}

/**
 * GIF：数帧。
 *
 * 帧 = Image Descriptor（分隔符 0x2C）。数到 2 就收工 —— 判断「是不是动图」
 * 不需要知道一共几帧，而早退能避免为了一个 3 MB 的 GIF 把整个文件读一遍。
 *
 * 文件头要单独算 Global Color Table 的长度再定位到第一个块：
 * Logical Screen Descriptor 第 7 字节的 bit7 是「有全局色表」，
 * 长度是 3 × 2^(N+1)，N 取低 3 位。漏了这一步的话第一个块会认错。
 */
function gifIsAnimated($fh, string $head): bool
{
    if (strlen($head) < 13) {
        return false;
    }
    $packed = ord($head[10]);
    $pos = 13 + (($packed & 0x80) ? 3 * (2 ** (($packed & 0x07) + 1)) : 0);
    if (fseek($fh, $pos) !== 0) {
        return false;
    }

    $frames = 0;
    while (!feof($fh)) {
        $b = fread($fh, 1);
        if ($b === false || $b === '') {
            break;
        }
        $c = ord($b);

        if ($c === 0x3B) {              // Trailer
            break;
        }

        if ($c === 0x2C) {               // Image Descriptor → 一帧
            if (++$frames >= 2) {
                return true;
            }
            // 越过 4 个 16 位字段（left/top/width/height）= 8 字节
            fseek($fh, 8, SEEK_CUR);
            $lb = fread($fh, 1);
            if ($lb === false || $lb === '') {
                break;
            }
            $lp = ord($lb);
            // 局部色表
            if (($lp & 0x80) !== 0) {
                fseek($fh, 3 * (2 ** (($lp & 0x07) + 1)), SEEK_CUR);
            }
            // LZW 数据：同样是一串 size(1)+data(size)，size==0 收尾
            if (!skipSubBlocks($fh)) {
                break;
            }
            continue;
        }

        if ($c === 0x21) {               // Extension：跳 label，再走子块
            fseek($fh, 1, SEEK_CUR);
            if (!skipSubBlocks($fh)) {
                break;
            }
            continue;
        }
        // 0x00 之类的填充字节，继续往下找
    }
    return false;
}

/**
 * 走完一串「长度字节 + 数据」子块，遇到长度为 0 的那个为止。
 * GIF 的图像数据、扩展数据都是这个结构。
 * 返回 false 表示文件在这个地方就断了（文件是截断的，按静态处理）。
 */
function skipSubBlocks($fh): bool
{
    for (;;) {
        $b = fread($fh, 1);
        if ($b === false || $b === '') {
            return false;
        }
        $n = ord($b);
        if ($n === 0) {
            return true;
        }
        if (fseek($fh, $n, SEEK_CUR) !== 0) {
            return false;
        }
    }
}

/**
 * WebP：容器里有 ANIM 块就是动图。
 *
 * 遍历 RIFF 里的 chunk 列表，按 FourCC 认。
 * 规格是 VP8X 的 flags 第 2 位（0x02）表示有动画，但那块是可写的
 * （可以置位而不给 ANIM，反过来不行），只看它不可靠。
 */
function webpIsAnimated($fh): bool
{
    if (fseek($fh, 12) !== 0) {     // 跳过 'RIFF' + size + 'WEBP'
        return false;
    }
    for (;;) {
        $hdr = fread($fh, 8);
        if ($hdr === false || strlen($hdr) < 8) {
            return false;
        }
        $id   = substr($hdr, 0, 4);
        $size = unpack('V', substr($hdr, 4, 4))[1];
        if ($id === 'ANIM' || $id === 'ANMF') {
            return true;
        }
        // chunk 数据按偶数字节补齐（odd-sized chunk 后面跟一个 0 填充字节）
        $step = $size + ($size % 2);
        if (fseek($fh, $step, SEEK_CUR) !== 0) {
            return false;
        }
    }
}

/**
 * PNG：APNG 的定义就是 acTL 出现在 IDAT 之前。
 * 顺序不能反 —— 放在 IDAT 之后的 acTL 是非法的（有的解码器当普通块忽略）。
 */
function pngIsAnimated($fh): bool
{
    if (fseek($fh, 8) !== 0) {
        return false;
    }
    for (;;) {
        $lenB = fread($fh, 4);
        if ($lenB === false || strlen($lenB) < 4) {
            return false;
        }
        $len = unpack('N', $lenB)[1];
        $id  = (string) fread($fh, 4);
        if (strlen($id) < 4) {
            return false;
        }
        if ($id === 'acTL') {
            return true;
        }
        if ($id === 'IDAT' || $id === 'IEND') {
            return false;
        }
        // 4 字节 CRC 不参与长度计算：长度 + 类型 + 数据 + 4
        if (fseek($fh, $len + 4, SEEK_CUR) !== 0) {
            return false;
        }
    }
}

// ====================================
// GD 转码
// ====================================

function loadImage(string $path, string &$err): ?GdImage
{
    if (!is_file($path) || !is_readable($path)) {
        $err = '上传临时文件不可读';
        return null;
    }
    $info = @getimagesize($path);
    if ($info === false) {
        $err = '不是可识别的图片格式';
        return null;
    }

    // AVIF 的类型常量不能直接写进 match 分支：IMAGETYPE_AVIF 是 PHP 8.3 才加的，
    // 老版本上引用未定义常量抛的是 Error（致命错误），不是 warning。
    // 那会让「传了张 avif」变成 500 白页，而不是一句能看懂的提示。
    // 所以先 defined() 问一句，取不到就用 -1 —— getimagesize 不会返回负数。
    $avifType = defined('IMAGETYPE_AVIF') ? IMAGETYPE_AVIF : -1;

    $im = match ($info[2]) {
        IMAGETYPE_PNG  => @imagecreatefrompng($path),
        IMAGETYPE_JPEG => @imagecreatefromjpeg($path),
        IMAGETYPE_WEBP => function_exists('imagecreatefromwebp') ? @imagecreatefromwebp($path) : null,
        IMAGETYPE_GIF  => @imagecreatefromgif($path),
        $avifType      => function_exists('imagecreatefromavif') ? @imagecreatefromavif($path) : null,
        default        => null,
    };
    if (!$im instanceof GdImage) {
        // 分开说，不然会把人往「内存不够」的方向带 ——
        // 之前 AVIF 走 default 分支时报的就是这句「格式不支持，或内存到顶」，
        // 而真实原因是压根没写那个分支。
        if ($info[2] === $avifType) {
            $err = '这台 PHP 解不了 AVIF：需要 8.3 以上，且编译时带了 libavif'
                 . '（查一下有没有 imageavif 支持）';
        } else {
            $err = '图片解码失败（格式不支持，或内存到顶）';
        }
        return null;
    }
    imagesavealpha($im, true);
    return $im;
}

/**
 * 取出要编码的图。源图已窄于目标 → 直接用源图（绝不放大），返回 owned=false，
 * 调用方不要销毁它；否则缩一份新的，返回 owned=true。
 */
function prepare(GdImage $src, int $targetW): array
{
    $w = imagesx($src);
    $h = imagesy($src);
    if ($w <= $targetW) {
        return [$src, false];
    }
    $newH = max(1, (int) round($h * $targetW / $w));
    $dst  = imagecreatetruecolor($targetW, $newH);
    imagealphablending($dst, false);
    imagesavealpha($dst, true);
    // 半透明像素缩小后会露出未初始化的黑底，先铺全透明
    imagefilledrectangle($dst, 0, 0, $targetW, $newH, imagecolorallocatealpha($dst, 0, 0, 0, 127));
    imagealphablending($dst, true);
    imagecopyresampled($dst, $src, 0, 0, 0, 0, $targetW, $newH, $w, $h);
    return [$dst, true];
}

function encodeTo(GdImage $im, string $path, int $q): bool
{
    return (bool) @imagewebp($im, $path, $q);
}

function dimOf(string $path): array
{
    $s = @getimagesize($path);
    return $s === false ? [0, 0] : [(int) $s[0], (int) $s[1]];
}

/**
 * 墓碑的键：`目录/文件名`，统一正斜杠
 * （Windows 上 str_replace 换掉反斜杠，否则同一个文件夹会开出两套键）。
 *
 * $dirAbs 一定在 IMAGES 之下（ensureFolder / resolveFolder 都走 safeJoinRoot），
 * 所以正常情况就是砍掉 IMAGES 前缀。这里仍然**显式校验**一遍：
 * 万一哪天传进来一个不在 images/ 下的路径，硬切 substr 会切出 `mages/foo/bar.png`
 * 这种垃圾键 —— 键错一位不会报错，只会让墓碑悄悄失效，正是这个函数要防的那类事。
 */
function tombstoneKey(string $dirAbs, string $filename): string
{
    $dirAbs = normPath($dirAbs);
    $base   = normPath(IMAGES);

    if ($dirAbs === $base) {
        $rel = '';
    } elseif (str_starts_with($dirAbs . '/', $base . '/')) {
        $rel = substr($dirAbs, strlen($base) + 1);
    } else {
        // 不在 images/ 下：拿绝对路径的哈希当命名空间。宁可键难看，
        // 也不能和某个真实目录的键撞上 —— 撞上等于给另一个文件夹点了火。
        $rel = '@' . substr(hash('sha256', $dirAbs), 0, 12);
    }
    return ($rel === '' ? '' : $rel . '/') . $filename;
}

/**
 * 读墓碑。文件坏了 / 被手改过 / 不存在，都当空的处理。
 *
 * 故意不报错：这份数据的唯一作用是「多给几个版本号」，一条坏记录的后果
 * 只是「删掉重传可能又看到旧图」—— 而那正是它要修的问题本身。
 * 因为一个坏 JSON 就拒绝上传，是拿自己修的病去给自己下药。
 */
function loadTombstones(): array
{
    $raw = @file_get_contents(TOMBSTONE_FILE);
    if (!is_string($raw) || $raw === '') {
        return [];
    }
    $j = json_decode($raw, true);
    if (!is_array($j) || !isset($j['names']) || !is_array($j['names'])) {
        return [];
    }
    $out = [];
    foreach ($j['names'] as $k => $sha) {
        if (is_string($k) && is_string($sha) && $sha !== '') {
            $out[$k] = $sha;
        }
    }
    return $out;
}

/** 原子写，和 saveSecret 同一个套路：先写临时文件再 rename */
function saveTombstones(array $names): bool
{
    if (!ensurePrivateDir()) {
        return false;
    }
    if (count($names) > TOMBSTONE_MAX_NAMES) {
        $names = array_slice($names, -TOMBSTONE_MAX_NAMES, null, true);
    }
    $body = json_encode(
        ['ver' => 1, 'names' => $names],
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT
    );
    if (!is_string($body)) {
        return false;
    }
    $tmp = TOMBSTONE_FILE . '.' . bin2hex(random_bytes(4)) . '.tmp';
    if (@file_put_contents($tmp, $body) !== strlen($body)) {
        @unlink($tmp);
        return false;
    }
    if (!@rename($tmp, TOMBSTONE_FILE)) {
        @unlink($tmp);
        return false;
    }
    @chmod(TOMBSTONE_FILE, 0600);
    return true;
}

/**
 * 烧掉一个文件名 —— 必须在 unlink / rename **之前**调用，
 * 那之后文件就没了，指纹取不到。
 *
 * 传进来的是「马上要消失的那个文件」。改名的话要烧的是**旧名字**：
 * 新名字那个文件还在，is_file 为真时会自然被占住，不用记。
 */
function burnFile(string $dirAbs, string $filename): bool
{
    $abs = $dirAbs . '/' . $filename;
    if (!is_file($abs)) {
        return false;
    }
    $sha = @hash_file('sha256', $abs);
    if (!is_string($sha) || $sha === '') {
        return false;
    }
    $names = loadTombstones();
    $names[tombstoneKey($dirAbs, $filename)] = $sha;
    return saveTombstones($names);
}

/**
 * 找一个未被占用、而且**从未发布过**的版本号。
 *
 * 内容一致则复用旧文件（不动 mtime，避免白打散 CDN 缓存）；
 * 内容不同则升 -v2 / -v3。
 *
 * 磁盘上没有、但墓碑里烧过的那个版本号有两条出路：
 *   - 指纹一样 → 说明是同一张图删了又传，还用同一个 URL，缓存依然有效
 *   - 指纹不同 → 这个地址已经在外面被缓存过了，绝不能复用，跳到下一版
 * 第二个分支就是「删掉重传还是旧图」的修法。
 *
 * $thumbExt 单独拎出来是因为动图：主文件保持原扩展名（不然动画没了），
 * 而缩略图必须是静态的 WebP —— 用主文件的扩展名会生成一张动图缩略图，
 * 列表页里就开始动了。
 *
 * 返回 [fullPath, thumbPath|null, suffix, reused, skippedBurned]
 *   reused        文件已在且内容相同，调用方不要写
 *   skippedBurned 本次跳过了至少一个「发布过又删掉」的版本号，
 *                 调用方据此提醒「博客里写死的旧 URL 该更新了」
 */
function resolveVersion(string $dir, string $stem, string $ext, string $tmpFull, bool $wantThumb, ?string $thumbExt = null): array
{
    $thumbExt ??= $ext;
    $sha     = hash_file('sha256', $tmpFull);
    $stones  = loadTombstones();
    $skipped = false;

    for ($v = 1; $v <= 99; $v++) {
        $suffix = $v === 1 ? '' : '-v' . $v;
        $full   = $dir . '/' . $stem . $suffix . '.' . $ext;
        $thumb  = $wantThumb ? $dir . '/' . $stem . $suffix . '-320.' . $thumbExt : null;

        if (is_file($full)) {
            if (filesize($full) === filesize($tmpFull)
                && hash_file('sha256', $full) === $sha) {
                return [$full, $thumb, $suffix, true, $skipped];
            }
            continue;
        }

        // 磁盘上没有这个名字 —— 它被用过吗？
        $burned = $stones[tombstoneKey($dir, $stem . $suffix . '.' . $ext)] ?? null;
        if (is_string($burned) && $burned !== '') {
            if ($burned === $sha) {
                // 同一张图删了又传。URL 不变，CDN 里的那份还是对的，直接写回去。
                // reused 仍然是 false —— 文件确实不在了，得真写。
                return [$full, $thumb, $suffix, false, $skipped];
            }
            $skipped = true;
            continue;
        }

        return [$full, $thumb, $suffix, false, $skipped];
    }
    throw new RuntimeException('同名文件已存在超过 99 个版本，请换个名字');
}

/** 把 $_FILES 的某个字段归一成行优先列表（PHP 可能给列优先结构） */
function normalizeFiles(array $field): array
{
    if ($field === []) {
        return [];
    }
    $first = reset($field);
    if (!is_array($first)) {
        return [];
    }
    if (!array_is_list($first)) {
        return array_values($field);
    }
    $out = [];
    foreach (array_keys($first) as $i) {
        $row = [];
        foreach ($field as $key => $col) {
            if (is_array($col) && array_key_exists($i, $col)) {
                $row[$key] = $col[$i];
            }
        }
        $out[] = $row;
    }
    return $out;
}

function uploadErrText(int $code): string
{
    return match ($code) {
        UPLOAD_ERR_INI_SIZE   => '超过 upload_max_filesize（' . iniHuman('upload_max_filesize') . '）',
        UPLOAD_ERR_FORM_SIZE  => '超过表单限制',
        UPLOAD_ERR_PARTIAL    => '只传了一半就断了',
        UPLOAD_ERR_NO_FILE    => '没有选择文件',
        UPLOAD_ERR_NO_TMP_DIR => '服务器没有临时目录',
        UPLOAD_ERR_CANT_WRITE => '服务器写临时文件失败',
        UPLOAD_ERR_EXTENSION  => '有 PHP 扩展拦下了这个上传',
        default               => '未知上传错误码 ' . $code,
    };
}

// ============================================================
// 全量备份：把 images/ 打成 ZIP
// ============================================================
//
// 为什么自己手写 zip 格式，不用 ZipArchive：
//
//   1. 这台主机的 disable_functions 里有 exec/shell_exec/system，
//      就算能装 zip 扩展，ZipArchive 只能在**磁盘上**生成文件，不能直接
//      写进响应。共享主机的磁盘配额通常比内存还紧，先落一份几十上百 MB
//      的临时文件是给自己找麻烦。
//   2. zip 扩展未必装了 —— 本机的便携 PHP 就没装，不能假设线上有。
//   3. 手写可以精确算出**压缩包的确切字节数**，于是能发 Content-Length。
//      这一点很关键：浏览器自己有进度条，中途断了也立刻发现，而不是
//      拿到一个「静默截断」的 zip —— 那种截断往往要到解压时才报出来，
//      而那时候备份已经没意义了。
//
// 压缩方式固定 store（不压缩）。WebP / JPEG / PNG / GIF / AVIF 本身
// 就是压缩格式，再 deflate 一遍 CPU 花掉了而体积几乎不动 —— 实测同一张
// 正文截图 store 和 deflate 差 0.3% 以内。省下来的 CPU 在免费主机上是实打实的。
//
// 内存占用是常数：每个文件先 hash_file() 算 CRC（一遍读），再分块流式写出
// （第二遍读）。两遍而不是一遍，是因为 zip 的 local header 里 CRC 字段在
// 文件头之前 —— 想一遍写完就只能用 data descriptor（标志位 0x0008），
// 而 Windows 资源管理器自带的解压器对 data descriptor 的 zip 支持很差。
//
// 不实现 ZIP64。四 gig 以上的备份在这个图床上不可能出现，真出现了也应该
// 明确报错，而不是写出一个能下载但解不开的包。

/** zip 的字节数上限（无 zip64 时）。超了就报错，不写坏包。 */
const ZIP_MAX_BYTES  = 0xFFFFFFFF;
const ZIP_MAX_FILES  = 0xFFFF;
/** 单个文件读进内存的分块大小。 */
const ZIP_CHUNK = 262144;

/**
 * unix 时间戳 → zip 用的 MS-DOS 时间/日期两个 16 位字。
 * zip 格式只从 1980 年开始，早于这个年份没有对应编码（会算成 1980）。
 */
function zipDosStamp(int $ts): array
{
    if ($ts < 315532800) {   // 1980-01-01 00:00:00 UTC
        $ts = 315532800;
    }
    $d = getdate($ts);
    return [
        (($d['hours'] << 11) | ($d['minutes'] << 5) | ($d['seconds'] >> 1)) & 0xFFFF,
        ((($d['year'] - 1980) << 9) | ($d['mon'] << 5) | $d['mday']) & 0xFFFF,
    ];
}

/**
 * fwrite() 是允许只写一部分的（socket 缓冲区满时很常见）。
 * 只调一次的话，文件会安静地少一截 —— 而 zip 少一截的最终症状是
 * 「压缩包损坏」，跟真正的原因隔了十万八千里。这里循环写到写完为止。
 */
function zipWrite($fh, string $bytes): void
{
    $n = strlen($bytes);
    $done = 0;
    while ($done < $n) {
        $w = @fwrite($fh, substr($bytes, $done));
        if ($w === false || $w === 0) {
            throw new RuntimeException('写响应时中断（已发出 ' . $done . ' / ' . $n . ' 字节）');
        }
        $done += $w;
    }
}

/**
 * 列出 images/ 下所有该备份的文件。
 *
 * 顺手把「读不了」的文件挑出来：这些必须在发响应头**之前**报出来。
 * 发完头就没法再返回 JSON 了，中途失败只能让用户拿到一个截断的 zip。
 *
 * @return array{0: list<array>, 1: list<string>}
 *         0 = 条目列表（按压缩包内路径排好序），1 = 读不了的文件
 */
function zipImageEntries(): array
{
    $base = realpath(IMAGES);
    if ($base === false) {
        return [[], []];
    }
    $base = normPath($base);

    $entries = [];
    $broken  = [];

    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::SELF_FIRST
        );
        foreach ($it as $info) {
            /** @var SplFileInfo $info */
            // 软链跳过：isFile() 对指向文件的软链也返回 true，跟着它读
            // 会把 images/ 之外的东西打进备份
            if ($info->isLink() || !$info->isFile()) {
                continue;
            }
            $name = $info->getFilename();
            if ($name === '' || $name[0] === '.') {
                continue;   // .htaccess、.gitkeep、.tmp-xxx 之类的中间产物
            }
            if (!in_array(strtolower($info->getExtension()), ALLOWED_EXT, true)) {
                continue;
            }
            $abs  = $info->getPathname();
            $size = @filesize($abs);
            if ($size === false || !@is_readable($abs)) {
                $broken[] = normPath(substr($abs, strlen($base)));
                continue;
            }
            $entries[] = [
                'zip'   => 'images/' . ltrim(normPath(substr($abs, strlen($base))), '/'),
                'path'  => $abs,
                'size'  => (int) $size,
                'mtime' => (int) @filemtime($abs),
                'crc'   => null,   // 算出来后再填，算一次就够
            ];
        }
    } catch (Throwable $e) {
        // 某个子目录进不去时，整棵树就扫不全。与其给一份「少了点东西」的
        // 备份让人误以为完整，不如直接失败。
        $broken[] = '(扫描中断：' . $e->getMessage() . ')';
        return [[], $broken];
    }

    // 固定顺序：同一个图库两次打包出来的字节流一致，方便对比
    usort($entries, static fn(array $a, array $b): int => strcmp($a['zip'], $b['zip']));
    return [$entries, $broken];
}

/**
 * 算出这个压缩包确切会有多少字节。
 *
 * 之所以能提前算准，是因为 store 方式下每个条目的长度只取决于文件名和
 * 原文件大小 —— 内容不影响长度。算准了就能发 Content-Length。
 */
function zipByteLength(array $entries): int
{
    $total = 22;   // EOCD
    foreach ($entries as $e) {
        $n = strlen($e['zip']);
        $total += 30 + $n + $e['size'];   // local header + 名字 + 数据
        $total += 46 + $n;                // central directory 一条
    }
    return $total;
}

/** 单个条目的 CRC-32。用 hash_file 而不是 crc32(fread(...))：一遍读，C 层实现。 */
function zipCrcOf(string $path): int
{
    $hex = @hash_file('crc32b', $path);
    if ($hex === false) {
        throw new RuntimeException('算不出校验值，可能文件刚被删了：' . $path);
    }
    // 必须走 hexdec：crc32() 在高位为 1 时给的是**有符号** int，
    // 直接 pack('V', 负数) 会写错四个字节，解出来就是坏文件。
    return (int) hexdec($hex);
}

/**
 * 备份包里附的清单。人看的那份。
 *
 * 特意不含口令哈希和 HMAC 密钥：这份 zip 只靠会话口令保护，
 * 而用户的口令本来就写在聊天记录里 —— 把密钥也塞进去只是让泄露面变大，
 * 换主机时重设一次口令就行。
 */
function zipManifestText(array $entries, int $totalBytes, array $broken = []): string
{
    $lines = [];
    $lines[] = 'Fuhao574 的图床 · 全量备份';
    $lines[] = str_repeat('=', 66);
    $lines[] = '生成时间   ' . date('Y-m-d H:i:s') . ' (' . date_default_timezone_get() . ')';
    $lines[] = '主机       https://' . PUBLIC_HOST . '/';
    $lines[] = '文件数     ' . count($entries);
    $lines[] = '图片体积   ' . fmtBytes($totalBytes);
    $lines[] = '压缩方式   不压缩（store）';
    $lines[] = '           WebP / JPEG / PNG / GIF / AVIF 本身就是压缩格式，';
    $lines[] = '           再压一遍 CPU 花掉了、体积几乎不变。省下来的算力';
    $lines[] = '           在免费主机上是实打实的，所以这里只打包不压缩。';
    $lines[] = str_repeat('-', 66);
    $lines[] = '目录结构';
    $lines[] = '  images/<文章 slug>/<文件名>.webp';
    $lines[] = '  文件夹名就是文章的 slug，和博客约定一致。';
    $lines[] = '  <slug>-cover.webp 是封面，<slug>-320.webp 是封面缩略图';
    $lines[] = '  （同一个文件夹里多出来的那张小图，博客列表页用）。';
    $lines[] = '  恢复：把 images/ 整个解压回网站根目录，URL 结构不用改。';
    $lines[] = str_repeat('-', 66);
    $lines[] = '这个包里没有什么';
    $lines[] = '  · 只有 images/ 下的图片，加这份清单和一个 manifest.json。';
    $lines[] = '  · 不含 index.php / lib.php / theme.css / index.html（图床程序）。';
    $lines[] = '  · 不含 private/（口令哈希和签名密钥）—— 换主机时重新设一次';
    $lines[] = '    口令就行，博客里已经写好的图片 URL 只要改主机名。';
    if ($broken !== []) {
        $lines[] = str_repeat('!', 66);
        $lines[] = '!!  注意：这份备份不完整，有 ' . count($broken) . ' 个文件没打进去';
        $lines[] = str_repeat('!', 66);
        foreach ($broken as $b) {
            $lines[] = '  缺  ' . $b;
        }
        $lines[] = '  （生成备份的那一刻它们读不到。换个时间再打一次，';
        $lines[] = '   拿文件数和下面这份清单对一下就知道补上没有。）';
    }
    $lines[] = str_repeat('-', 66);
    $lines[] = '文件清单（路径 / 字节 / 最后修改时间）';
    $lines[] = str_repeat('-', 66);
    foreach ($entries as $e) {
        $lines[] = sprintf(
            '%-52s %10s  %s',
            $e['zip'],
            number_format($e['size']),
            date('Y-m-d H:i:s', $e['mtime'])
        );
    }
    $lines[] = '';
    return implode("\n", $lines);
}

/** 同一份清单的机器可读版本。换到新主机后可以拿它对一遍少没少文件。 */
function zipManifestJson(array $entries, int $totalBytes, array $broken = []): string
{
    $files = [];
    foreach ($entries as $e) {
        $files[] = [
            'path'  => $e['zip'],
            'bytes' => $e['size'],
            'mtime' => $e['mtime'],
            'crc32' => sprintf('%08x', $e['crc'] ?? 0),
        ];
    }
    return (string) json_encode([
        'generator' => SITE_PRODUCT,
        'host'      => 'https://' . PUBLIC_HOST . '/',
        'createdAt' => date('c'),
        'count'     => count($entries),
        'bytes'     => $totalBytes,
        // 有缺口时这个字段非空。自动化脚本应该检查它 ——
        // 只看 files 的话，「下载成功」和「备份完整」是俩码事。
        'missing'   => array_values($broken),
        'files'     => $files,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
}

/**
 * 打包前先算一次，把体量告诉前端。
 *
 * 存在的意义：点一下就开下一个几十兆的请求，用户是没有退路的。
 * 先报「多少个文件、多大、可能会超时」，让他自己决定。
 */
function backupStats(): array
{
    [$entries, $broken] = zipImageEntries();
    $bytes = array_sum(array_column($entries, 'size'));
    return [
        'ok'       => true,
        'files'    => count($entries),
        'bytes'    => $bytes,
        'broken'   => $broken,
        'warnings' => zipWarnings(count($entries), $bytes, $broken),
    ];
}

/**
 * 什么情况下该提醒一句。
 *
 * 这里的 "\n" 是真换行 —— 这些文字走 JSON 出去，前端 confirm() 里直接就是
 * 换行。**不能**写成 {$nl}：那个插值只在 heredoc 里生效，这里是普通函数，
 * 写上去就是字面的 {$nl} 三个字符出现在弹窗里。
 *
 * 共享主机的三重限制都会在这时候咬人：max_execution_time、
 * 磁盘/流量配额、以及 Cloudflare 那边的代理超时。所以阈值不是拍脑袋，
 * 是「超过这个量级就大概率会中途断」的经验值 —— 说实话比假装没事好。
 */
function zipWarnings(int $files, int $bytes, array $broken): array
{
    $w = [];
    if ($broken !== []) {
        $w[] = '有 ' . count($broken) . ' 个文件读不了，这次不会包含它们：'
             . implode('、', array_slice($broken, 0, 3))
             . (count($broken) > 3 ? ' 等' : '')
             ."\n备份照样会生成，但清单里会明确列出少了哪些。";
    }
    if ($files === 0) {
        $w[] = 'images/ 下没有可备份的文件。';
        return $w;
    }
    if ($files > ZIP_MAX_FILES) {
        $w[] = '文件数超过 ' . ZIP_MAX_FILES . ' 个，压缩包格式放不下，请分批处理。';
    }
    if ($bytes > ZIP_MAX_BYTES) {
        $w[] = '总体积超过 4 GB，当前格式放不下。';
    }
    // 200 MB 是经验线：免费共享主机上这个量级经常撞上执行超时或流量限制，
    // 中途断了就白等一场。低于它基本不会出事，就不打扰用户了。
    if ($bytes > 200 * 1024 * 1024) {
        $w[] = '图片总体积 ' . fmtBytes($bytes) . '，比较大。'
             . '免费主机的执行超时和流量限制经常在这个量级上咬人，'
             . '中途断掉的话浏览器会明确报「下载不完整」，不会给你一个悄悄'
             . '截断的包 —— 真断了就分几次传，或者先把不常用的挪走。';
    }
    if ($files > 3000) {
        $w[] = '文件数 ' . $files . ' 个，逐个文件的开销也上来了。';
    }
    return $w;
}

/**
 * 真正把 zip 流式写出去。
 *
 * 走顶层导航（GET），不走 fetch + Blob，两个原因：
 *   1. 几十上百 MB 用 Blob 接的话，浏览器内存里会同时存两份（网络缓冲 + Blob）。
 *   2. 这台主机的反爬挑战靠**顶层导航**才能过（fetch 拿到的只是文本）。
 *      用导航顺带就绕开了这个坑，不用额外做什么。
 */
function streamImagesZip(): never
{
    [$entries, $broken] = zipImageEntries();

    // 读不了的文件**不**让整个备份失败。
    // 一开始这里是直接报错的，想的是「宁可不打包，也不要给一份缺东西的备份」。
    // 但这个功能的场景恰恰是「主机快不行了，我得赶紧把东西捞出来」——
    // 这时候一个文件读不出来（权限抽风、正好被上传过程占用）就把全部
    // 堵死，是最坏的时机做最坏的决定。所以改成：照样打包，但在两个地方
    // 把缺口说明白 —— 下载前的确认框、以及包里的清单第一屏。
    if ($entries === []) {
        jsonOut(['ok' => false, 'error' => 'images/ 下没有可备份的文件'], 404);
    }
    if (count($entries) > ZIP_MAX_FILES) {
        jsonOut(['ok' => false, 'error' => '文件数超过 ' . ZIP_MAX_FILES . ' 个，压缩包格式放不下'], 500);
    }

    // CRC 必须**在发头之前**算完：header() 一旦发出去就撤不回来了，
    // 而 CRC 要写进每个条目的文件头。
    foreach ($entries as $i => $e) {
        $entries[$i]['crc'] = zipCrcOf($e['path']);
    }

    // 清单放最前面。它自己也当成普通条目走同一套写出逻辑 ——
    // 单独为它写一份特例就等于多了两条会漂开的路径。
    $stamp = time();
    $sum   = array_sum(array_column($entries, 'size'));
    $extra = [];
    foreach ([
        ['zip' => '_backup-manifest.txt', 'text' => zipManifestText($entries, $sum, $broken)],
        ['zip' => '_backup-manifest.json', 'text' => zipManifestJson($entries, $sum, $broken)],
    ] as $e) {
        $extra[] = [
            'zip'   => $e['zip'],
            'path'  => null,
            'text'  => $e['text'],
            // size 也得填上：zipByteLength() 算总长时按 size 取每条的数据量，
            // 清单条目缺这个键就直接崩在那儿 —— 而且是在 header() 之后崩。
            'size'  => strlen($e['text']),
            'mtime' => $stamp,
            'crc'   => null,
        ];
    }
    $items = array_merge($extra, $entries);

    $size = 0;
    foreach ($items as $it) {
        $size += $it['path'] === null ? strlen($it['text']) : $it['size'];
    }
    $total = zipByteLength($items);
    if ($total > ZIP_MAX_BYTES) {
        jsonOut(['ok' => false, 'error' => '压缩包会超过 4 GB，当前格式放不下'], 500);
    }

    // 清掉输出缓冲。开着缓冲的话，前 4KB 会一直攒着，浏览器那边一个字都收不到；
    // 更糟的是二进制被攒进缓冲再一次性吐出，Content-Length 就对不上了。
    while (ob_get_level() > 0) {
        @ob_end_clean();
    }
    @ini_set('zlib.output_compression', 'Off');
    @ini_set('output_buffering', 'Off');
    if (function_exists('apache_setenv')) {
        // 有些主机的 mod_deflate 会对 application/zip 下手，一压就全毁了
        @apache_setenv('no-gzip', '1');
    }
    // 流式写响应不算 CPU 时间（非 Windows 上 PHP 的行为），但显式放开更稳。
    // 有些主机把 set_time_limit 禁了，用 @ 压掉警告。
    @set_time_limit(0);
    @ignore_user_abort(false);

    $stampTxt = date('Ymd-His', $stamp);
    $asciiName = 'fuhao574-images-' . $stampTxt . '.zip';
    $utf8Name  = 'Fuhao574-图床备份-' . $stampTxt . '.zip';

    header('Content-Type: application/zip');
    // 两个 filename 都给：filename 是 ASCII 兜底（旧浏览器认它），
    // filename* 才是标准的中文文件名写法。
    header('Content-Disposition: attachment; filename="' . $asciiName . '"; '
         . "filename*=UTF-8''" . rawurlencode($utf8Name));
    header('Content-Length: ' . $total);
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    header('X-Robots-Tag: noindex, nofollow');

    $fh = @fopen('php://output', 'wb');
    if ($fh === false) {
        error_log('[imghost] 开不了 php://output');
        exit;
    }

    $offsets = [];
    try {
        foreach ($items as $it) {
            [$dosTime, $dosDate] = zipDosStamp($it['path'] === null ? $stamp : $it['mtime']);
            $name = $it['zip'];
            $n    = strlen($name);
            $data = $it['path'] === null ? strlen($it['text']) : $it['size'];
            $crc  = $it['path'] === null ? (int) hexdec(hash('crc32b', $it['text'])) : $it['crc'];

            $offsets[] = ['name' => $name, 'crc' => $crc, 'data' => $data,
                          'time' => $dosTime, 'date' => $dosDate, 'off' => ftell($fh)];

            // local file header
            zipWrite($fh, pack('VvvvvvVVVvv',
                0x04034b50,   // 签名
                20,           // 解压所需版本 2.0（store 不需要更高）
                0x0800,       // 通用标志位 bit11 = 文件名是 UTF-8
                0,            // 压缩方式 0 = store
                $dosTime, $dosDate,
                $crc,
                $data, $data,
                $n, 0         // 文件名长度、扩展字段长度
            ) . $name);

            // 数据本体
            if ($it['path'] === null) {
                zipWrite($fh, $it['text']);
            } else {
                $in = @fopen($it['path'], 'rb');
                if ($in === false) {
                    throw new RuntimeException('文件读不到了（可能刚被删）：' . $it['zip']);
                }
                try {
                    while (!feof($in)) {
                        $buf = fread($in, ZIP_CHUNK);
                        if ($buf === false) {
                            throw new RuntimeException('读中断：' . $it['zip']);
                        }
                        if ($buf !== '') {
                            zipWrite($fh, $buf);
                        }
                    }
                } finally {
                    fclose($in);
                }
            }
        }

        // central directory
        $cdStart = ftell($fh);
        foreach ($offsets as $o) {
            zipWrite($fh, pack('VvvvvvvVVVvvvvvVV',
                0x02014b50,   // 签名
                20, 20,       // 生成方版本、解压所需版本
                0x0800, 0,
                $o['time'], $o['date'],
                $o['crc'],
                $o['data'], $o['data'],
                strlen($o['name']), 0, 0,   // 名长、扩展长、注释长
                0, 0,          // 起始盘号、内部属性
                0,             // 外部属性
                $o['off']
            ) . $o['name']);
        }
        $cdSize = ftell($fh) - $cdStart;

        // EOCD
        zipWrite($fh, pack('VvvvvVVv',
            0x06054b50,
            0, 0,
            count($offsets), count($offsets),
            $cdSize, $cdStart,
            0
        ));
    } catch (Throwable $e) {
        // 到这儿响应头已经发出去了，没法再报错，只能记日志。
        // 好在 Content-Length 早就报过了，浏览器会自己发现截断。
        error_log('[imghost] 备份中断：' . $e->getMessage());
        exit;
    }

    fclose($fh);
    exit;
}
