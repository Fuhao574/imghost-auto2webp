<?php

declare(strict_types=1);

/**
 * index.php — Fuhao574 的图床：登录页 + 上传 + 图库管理
 *
 * 部署：把 index.php 与 lib.php 传到图床 web 根目录（与 images/ 同级）。
 * 若主机自带 index.html 停放页，删掉它或让本文件接管 DirectoryIndex。
 *
 * 路由：
 *   GET  /                    未登录 → 登录页；已登录 → 图床
 *   POST ?do=login            登录（非 ajax 时 302 回 index.php）
 *   GET  ?do=logout           登出
 *   POST ?do=api:upload       上传（multipart，一次最多 MAX_FILES 张）
 *   POST ?do=api:delete       删文件
 *   POST ?do=api:delfolder    删空文件夹
 *   POST ?do=api:rename       改名（kind=file|folder）
 *   POST ?do=api:newfolder    新建空文件夹
 *   POST ?do=api:changepw      改口令
 *   POST ?do=api:list         图库 JSON
 *   POST ?do=api:backupinfo   备份体量（几个文件、多大、有没有风险）
 *   GET  ?do=download         全量备份 zip（流式输出，不落盘）
 *
 *   未列出的：GET ?do=whoami / ?do=guardstatus 是公开探测端点，
 *   只回答「这个浏览器登录了吗 / 这个 IP 还能不能试」，不泄露图库数据。
 *
 *   api: 开头的一律要登录 + CSRF 校验；login / whoami / guardstatus /
 *   download 不走 api: 分支（前者是表单，后者是文件下载）。
 */

require __DIR__ . '/lib.php';

boot();

if (!is_dir(IMAGES) && !@mkdir(IMAGES, 0755, true) && !is_dir(IMAGES)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "建不出 images/ 目录，请检查权限。\n";
    exit;
}

if (!extension_loaded('gd') || !function_exists('imagewebp')) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=utf-8');
    echo "这台机器的 GD 不能写 WebP，图床不可用。\n";
    exit;
}

$action = (string) ($_GET['do'] ?? $_POST['do'] ?? '');

// ============================================================
// 登录 / 登出
// ============================================================

if ($action === 'login') {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        header('Location: ' . strtok($_SERVER['REQUEST_URI'] ?? '/', '?'));
        exit;
    }
    // ajax=1：给 index.html 那个静态登录页用 —— 它用 fetch 提交，
    // 要的是 JSON 而不是整页 HTML。缺这个参数时行为和以前一样（表单 POST + 302）。
    $ajax = ($_GET['ajax'] ?? '') === '1';

    /**
     * 爆破防护，三层，从便宜到贵（详见 lib.php 的 GUARD_* 注释）：
     *   1. 正锁着 → 立刻拒，**不跑 bcrypt**
     *   2. 递增等待（按这个 IP 之前失败几次决定等多久）
     *   3. 口令错 → 记一次，可能就此锁定
     *
     * 顺序很要紧：先看锁、再等、最后才验口令。反过来的话，锁定期间
     * 每一次请求还是要白白消耗一次 bcrypt cost 12，防护就只剩心理作用了。
     */
    $st = guardStatus();

    if ($st['locked']) {
        // 锁定期间不区分「口令对不对」，一律拒。否则就成了一个口令探测 oracle。
        $msg = '尝试次数过多，已临时锁定，请 ' . $st['retryAfter'] . ' 秒后再试。';
        if ($ajax) {
            jsonOut([
                'ok'         => false,
                'error'      => $msg,
                'locked'     => true,
                'retryAfter' => $st['retryAfter'],
            ], 429);
        }
        renderLogin($msg, 429);
    }

    if ($st['fails'] > 0) {
        // 递增等待。拿着 PHP worker 干等本身就是成本。
        // 按执行时间预算封顶 —— 睡过头 PHP 会把请求掐掉变成 500，
        // 而且失败记录来不及写，计数就卡在这一档。详见 guardSleepBudget()。
        sleep(min($st['backoff'], guardSleepBudget()));
    }

    $pw     = (string) ($_POST['password'] ?? '');
    $cookie = makeAuthCookie($pw);

    if ($cookie === null) {
        $after = guardFail();
        if ($after['locked']) {
            $msg = '尝试次数过多，已锁定 ' . (int) round(GUARD_LOCK_SECS / 60) . ' 分钟。';
        } elseif ($after['left'] <= 3) {
            // 剩不多的时候提醒一下。这是单人使用的工具，提示比装糊涂有用。
            $msg = '口令不对。还可以再试 ' . $after['left'] . ' 次，之后锁定 '
                 . (int) round(GUARD_LOCK_SECS / 60) . ' 分钟。';
        } else {
            $msg = '口令不对，再试一次。';
        }

        if ($ajax) {
            jsonOut([
                'ok'         => false,
                'error'      => $msg,
                'locked'     => $after['locked'],
                'retryAfter' => $after['retryAfter'],
                'left'       => $after['left'],
                // 让前端能提示「再错一次要等 N 秒」
                'nextWait'   => $after['backoff'],
            ], $after['locked'] ? 429 : 401);
        }
        renderLogin($msg, $after['locked'] ? 429 : 401);
    }

    guardReset();
    sendAuthCookie($cookie);

    if ($ajax) {
        jsonOut(['ok' => true, 'redirect' => 'index.php']);
    }

    // 注意：跳转目标必须是 index.php，不能是 /。
    // 根路径命中的是静态 index.html（登录页），转回 / 会变成「登录成功 → 又看到登录页」的死循环。
    header('Location: index.php');
    exit;
}

/**
 * 登录状态探测。静态 index.html 加载后调它：已登录就直接跳进图床，
 * 免得让已经登录的人再输一遍口令。
 *
 * 这是个公开端点，但只回答「当前这个浏览器有没有登录」，不泄露任何图库数据，
 * 也不泄露口令材料 —— 换个浏览器问就得到 false，仅此而已。
 */
if ($action === 'whoami') {
    jsonOut([
        'ok'     => true,
        'authed' => authed(),
        'csrf'   => authed() ? csrfToken() : null,
    ]);
}

/**
 * 锁定状态探测。公开端点，但只回答「这个 IP 现在能不能试」——
 * 泄露的只有「你自己有没有被锁」，换个人问得到的是他自己的状态。
 *
 * 存在的意义：锁定可能发生在上一个标签页。不问的话，用户要填完口令
 * 点「进入」、等服务端睡完那几秒，才知道自己被锁了 15 分钟。
 */
if ($action === 'guardstatus') {
    $st = guardStatus();
    jsonOut([
        'ok'         => true,
        'locked'     => $st['locked'],
        'retryAfter' => $st['retryAfter'],
        'left'       => $st['left'],
        // 只说「要不要改口令」，不说口令本身。
        // 静态登录页拿这一条就能提示「去 index.php 看初始口令」，
        // 而不用把口令暴露给任何走 / 进来的人。
        'mustChange' => secret()['mustChange'],
    ]);
}

if ($action === 'logout') {
    sendAuthCookie(null);
    // 登出后回静态登录页。这里用 / 是对的 —— index.html 就是登录页。
    header('Location: ./');
    exit;
}

/**
 * 全量备份下载。GET，不是 api:。
 *
 * 为什么不进 api: 分支：那里会走 CSRF 校验和 JSON，而这是个**文件下载**，
 * 要的是 Content-Disposition 和二进制响应体。走 POST + fetch + Blob 的话，
 * 几百 MB 会在浏览器内存里存两份，而且这台主机的反爬挑战只在顶层导航时
 * 才能过，fetch 拿到的挑战页浏览器根本不执行 —— 顶层导航顺带把这坑绕开了。
 *
 * CSRF：这是个只读端点，跨站页面即使触发了下载也拿不到内容
 * （没有 CORS 头，浏览器不会把响应交给发起方），最坏情况是用户浏览器
 * 里多弹一次下载。所以只要求会话登录，不额外加令牌。
 */
if ($action === 'download') {
    if (!authed()) {
        header('Location: ./');
        exit;
    }
    streamImagesZip();
}

// ============================================================
// API（全部需要登录 + CSRF）
// ============================================================

if (str_starts_with($action, 'api:')) {
    if (!authed()) {
        jsonOut(['ok' => false, 'error' => '未登录或登录已过期'], 401);
    }
    if (!checkCsrf()) {
        jsonOut(['ok' => false, 'error' => 'CSRF 校验失败，刷新页面重试'], 403);
    }
    $api = substr($action, 4);

    // 首次部署生成的那个口令，必须改掉才能继续用。
    // 唯一的例外就是改口令本身 —— 不然就成死循环了。
    //
    // 为什么非得强制：那个口令是随机生成的，但明文暂存在 private/ 里，
    // 而且会在登录页上显示出来。在主人改掉之前，知道它的人就能进来看图、
    // 删图。留着「改不改随你」等于白生成。
    if (secret()['mustChange'] && $api !== 'changepw') {
        jsonOut([
            'ok'         => false,
            'mustChange' => true,
            'error'      => '当前还在用首次部署生成的口令。先改掉它（图床右下角「改口令」），其它操作才能用。',
        ], 403);
    }

    match ($api) {
        'upload'    => apiUpload(),
        'delete'    => apiDelete(),
        'delfolder' => apiDelFolder(),
        'rename'    => apiRename(),
        'newfolder' => apiNewFolder(),
        'changepw'  => apiChangePassword(),
        'list'      => jsonOut(['ok' => true, 'groups' => scanImages()]),
        'backupinfo' => jsonOut(backupStats()),
        default     => jsonOut(['ok' => false, 'error' => '未知操作'], 404),
    };
}

if (!authed()) {
    renderLogin();
}

renderDashboard();

// ============================================================
// 上传
// ============================================================

/**
 * 动图上传：原样保存，不转码。
 *
 * 为什么要单独一条路：GD 的解码器只取第一帧。动图走正常流程的话，
 * 转出来的 WebP 是**静**的 —— 动画没了，而且用户根本看不出来
 * （图还在显示，只是不动）。静默丢数据比报错糟糕得多，
 * 所以宁可体积大一点，也要把原文件整份留着。
 *
 * 代价是体积由用户说了算：普通图出来是 WebP，最多几十 KB；
 * 动图原样落盘，一个 3 MB 的 GIF 就是 3 MB，之后每次浏览都在花这个钱。
 * 所以卡一道 ANIM_MAX_BYTES，并且超了要说清楚「动图不压缩，
 * 你上传多大就存多大」，别让人以为是图床在乱收费。
 *
 * 缩略图尽力而为：静态缩略图要从第一帧生成，而 GD 读不了动图 WebP
 * （它的 webp 解码器只认简单格式，不认 RIFF 容器）。这时候**不报错** ——
 * 主文件已经好好存着了，为一张可有可无的缩略图把整次上传判失败是本末倒置。
 *
 * 返回值和转码那条路一样是 $results 里的一项，字段名保持一致，
 * 多一个 animated 标记，前端据此说明「这张没转码」。
 */
function saveAnimatedOriginal(
    string $tmpIn,
    string $origName,
    string $dir,
    string $folder,
    string $stem,
    bool $wantThumb,
    float $t0
): array {
    $bytes = (int) filesize($tmpIn);
    if ($bytes > ANIM_MAX_BYTES) {
        return [
            'ok'     => false,
            'folder' => $folder,
            'name'   => $origName,
            'error'  => '动图 ' . fmtBytes($bytes) . '，超过 ' . fmtBytes(ANIM_MAX_BYTES)
                     . ' 的上限。动图不压缩、原样保存，所以图床占多大就是它自己多大。'
                     . '想压小就在本地先转一遍，或者截几帧。',
        ];
    }

    // 存成什么扩展名，**按内容判，不按文件名判**。
    //
    // 原文件名只是个线索：用户完全可能把 GIF 传成 x.png（或者干脆
    // 不带扩展名），这时候信文件名就会给一个 GIF 内容套上 .png 的壳。
    // 转码那条路本来就是靠 getimagesize 认类型的，动图这条路跟着一致，
    // 两边对同一个文件的判断不会打架。
    //
    // 认不出 mime 才退回文件名，且仍然要过 ALLOWED_EXT ——
    // 前端只按 MIME 过滤，脚本化上传（curl）什么都能塞进来。
    $info = @getimagesize($tmpIn);
    $mime = is_array($info) ? (string) ($info['mime'] ?? '') : '';
    $ext  = match ($mime) {
        'image/gif'  => 'gif',
        'image/webp' => 'webp',
        'image/png'  => 'png',   // APNG 的 MIME 也是 image/png
        'image/avif' => 'avif',
        default      => strtolower(pathinfo($origName, PATHINFO_EXTENSION)),
    };
    if (!in_array($ext, ALLOWED_EXT, true)) {
        return [
            'ok'     => false,
            'folder' => $folder,
            'name'   => $origName,
            'error'  => '动图只能存这些格式：' . implode('、', ALLOWED_EXT)
                     . ($mime !== '' ? '（这个文件识别出来是 ' . $mime . '）' : ''),
        ];
    }

    $dim = dimOf($tmpIn);
    if ($dim[0] === 0) {
        return ['ok' => false, 'folder' => $folder, 'name' => $origName,
                'error' => '读不出动图的尺寸，文件可能损坏'];
    }

    $tmpFull = $dir . '/.tmp-' . bin2hex(random_bytes(6)) . '.' . $ext;
    if (!@copy($tmpIn, $tmpFull)) {
        return ['ok' => false, 'folder' => $folder, 'name' => $origName,
                'error' => '临时文件写不出来，检查目录权限和磁盘空间'];
    }

    try {
        // 缩略图永远是静态 WebP，哪怕主文件是 .gif
        [$fullPath, $thumbPath, $suffix, $reused] = resolveVersion(
            $dir, $stem, $ext, $tmpFull, $wantThumb, 'webp'
        );

        if ($reused) {
            $dim = dimOf($fullPath);
        } elseif (!@rename($tmpFull, $fullPath)) {
            return ['ok' => false, 'folder' => $folder, 'name' => $origName,
                    'error' => '落盘失败：' . basename($fullPath)];
        } else {
            $tmpFull = null;

            if ($thumbPath !== null) {
                // 从第一帧出静态缩略图。读不出来就算了，主文件已经存好了。
                $err = '';
                $src = loadImage($tmpIn, $err);
                if ($src instanceof GdImage) {
                    try {
                        [$tim, $tOwned] = prepare($src, COVER_THUMB);
                        $wrote = encodeTo($tim, $thumbPath, COVER_THUMB_Q);
                        if ($tOwned) {
                            imagedestroy($tim);
                        }
                        if (!$wrote) {
                            @unlink($thumbPath);
                        }
                    } finally {
                        imagedestroy($src);
                    }
                }
                if (!is_file($thumbPath)) {
                    $thumbPath = null;   // 这台机器解不了这类动图，就不给缩略图
                }
            }
        }

        $fullBytes = (int) filesize($fullPath);
        $rel       = $folder . '/' . basename($fullPath);
        $url       = imgUrl($rel);

        $item = [
            'ok'        => true,
            'mode'      => $wantThumb ? 'cover' : 'normal',
            'folder'    => $folder,
            'version'   => $suffix === '' ? '(首发)' : $suffix,
            'identical' => $reused,
            'animated'  => true,
            'source'    => ['w' => $dim[0], 'h' => $dim[1], 'bytes' => $bytes],
            'file'      => [
                'url'   => $url,
                'path'  => $rel,
                'name'  => basename($fullPath),
                'w'     => $dim[0], 'h' => $dim[1],
                'bytes' => $fullBytes,
            ],
            'ms'        => (int) round((microtime(true) - $t0) * 1000),
            // 原样保存 = 一个字节都没省，别让「省 0%」看起来像个 bug
            'saved'     => 0,
            'notUpscaled' => true,
        ];

        if ($thumbPath !== null && is_file($thumbPath)) {
            $td = dimOf($thumbPath);
            $item['thumb'] = [
                'url'   => imgUrl($folder . '/' . basename($thumbPath)),
                'path'  => $folder . '/' . basename($thumbPath),
                'name'  => basename($thumbPath),
                'w'     => $td[0], 'h' => $td[1],
                'bytes' => (int) filesize($thumbPath),
            ];
        }

        return $item;
    } finally {
        if ($tmpFull !== null && is_file($tmpFull)) {
            @unlink($tmpFull);
        }
    }
}

function apiUpload(): never
{
    $mode    = (($_POST['mode'] ?? 'normal') === 'cover') ? 'cover' : 'normal';
    // 界面上没有「最大宽」输入框了，走常量。仍然接受 POST 里的 maxW，
    // 这样脚本化上传（curl / 自己的脚本）还能指定宽度。
    $maxW    = max(64, min(6000, (int) ($_POST['maxW'] ?? NORMAL_MAX_W)));
    $q       = max(30, min(100, (int) ($_POST['q'] ?? NORMAL_Q)));
    $folders = (array) ($_POST['folders'] ?? []);
    $names   = (array) ($_POST['names'] ?? []);

    if (!isset($_FILES['files'])) {
        $cl   = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        $post = iniBytes('post_max_size');
        jsonOut([
            'ok'    => false,
            'error' => match (true) {
                $cl === 0            => '请求体是空的：表单太大被服务器在解析前丢弃了',
                $post !== null && $cl > $post
                                     => '请求体 ' . number_format($cl) . ' 字节，超过 post_max_size（' . iniHuman('post_max_size') . '）',
                default              => 'PHP 没收到文件字段，检查字段名是不是 files[]',
            },
            'env'   => [
                'post_max_size'       => iniHuman('post_max_size'),
                'upload_max_filesize' => iniHuman('upload_max_filesize'),
                'CONTENT_LENGTH'      => number_format($cl) . ' 字节',
            ],
        ]);
    }

    $results    = [];
    $i          = 0;
    $overflowed = false;

    foreach (normalizeFiles($_FILES['files']) as $f) {
        if ($i >= MAX_FILES) {
            $overflowed = true;
            break;
        }
        $origName = (string) ($f['name'] ?? 'image');
        $folderIn = (string) ($folders[$i] ?? '');
        $nameIn   = (string) ($names[$i] ?? '');
        $i++;

        // 文件夹没填就从原文件名推（去扩展名）
        if (trim($folderIn) === '') {
            $folderIn = pathinfo($origName, PATHINFO_FILENAME);
        }
        $folder = sanitizeFolder($folderIn);

        try {
            if ($folder === '') {
                throw new RuntimeException('文件夹名不合法：只允许字母数字、点、下划线、连字符，且不能以点开头');
            }
            if (($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                throw new RuntimeException(uploadErrText((int) ($f['error'] ?? UPLOAD_ERR_NO_FILE)));
            }

            $dir = ensureFolder($folder);
            if ($dir === null) {
                throw new RuntimeException('建不出目录 / ' . $folder);
            }

            $tmpIn = (string) ($f['tmp_name'] ?? '');
            $err   = '';
            $t0    = microtime(true);

            // 封面模式：强制 <folder>-cover，宽度固定，与博客约定对齐
            $stem = $mode === 'cover' ? $folder . '-cover' : sanitizeStem($nameIn !== '' ? $nameIn : pathinfo($origName, PATHINFO_FILENAME));
            if ($stem === '') {
                throw new RuntimeException('文件名不合法');
            }

            // 动图在解码之前就得分流。放在后面判就晚了：GD 已经把第一帧
            // 读出来，动画没了，那时候再说什么都补不回来。
            if (isAnimated($tmpIn)) {
                $results[] = saveAnimatedOriginal(
                    $tmpIn, $origName, $dir, $folder, $stem, $mode === 'cover', $t0
                );
                continue;
            }

            $src = loadImage($tmpIn, $err);
            if ($src === null) {
                throw new RuntimeException($err);
            }

            $tmpFull = null;
            try {
                $srcW     = imagesx($src);
                $srcH     = imagesy($src);
                $srcBytes = is_file($tmpIn) ? (int) filesize($tmpIn) : 0;

                $target = $mode === 'cover' ? COVER_W : $maxW;
                $qual   = $mode === 'cover' ? COVER_Q : $q;

                $tmpFull = $dir . '/.tmp-' . bin2hex(random_bytes(6)) . '.webp';
                [$im, $owned] = prepare($src, $target);
                $dim  = [imagesx($im), imagesy($im)];
                $ok   = encodeTo($im, $tmpFull, $qual);
                if ($owned) {
                    imagedestroy($im);
                }
                if (!$ok) {
                    throw new RuntimeException('imagewebp 写失败，多半是 memory_limit 到顶');
                }

                [$fullPath, $thumbPath, $suffix, $reused] = resolveVersion(
                    $dir,
                    $stem,
                    'webp',
                    $tmpFull,
                    $mode === 'cover'
                );

                if ($reused) {
                    // 内容一致：保留旧文件，不动 mtime，免得白打散 Cloudflare 缓存
                    $dim      = dimOf($fullPath);
                    $thumbDim = $thumbPath !== null ? dimOf($thumbPath) : null;
                } else {
                    if (!@rename($tmpFull, $fullPath)) {
                        throw new RuntimeException('落盘失败：' . basename($fullPath));
                    }
                    $tmpFull = null;

                    $thumbDim = null;
                    if ($thumbPath !== null) {
                        [$tim, $tOwned] = prepare($src, COVER_THUMB);
                        $thumbDim = [imagesx($tim), imagesy($tim)];
                        $tOk = encodeTo($tim, $thumbPath, COVER_THUMB_Q);
                        if ($tOwned) {
                            imagedestroy($tim);
                        }
                        if (!$tOk) {
                            throw new RuntimeException('缩略图写失败');
                        }
                    }
                }

                $fullBytes = (int) filesize($fullPath);
                $rel       = $folder . '/' . basename($fullPath);
                $url       = imgUrl($rel);

                $item = [
                    'ok'        => true,
                    'mode'      => $mode,
                    'folder'    => $folder,
                    'version'   => $suffix === '' ? '(首发)' : $suffix,
                    'identical' => $reused,
                    'source'    => ['w' => $srcW, 'h' => $srcH, 'bytes' => $srcBytes],
                    'file'      => [
                        'url'   => $url,
                        'path'  => $rel,
                        'name'  => basename($fullPath),
                        'w'     => $dim[0], 'h' => $dim[1],
                        'bytes' => $fullBytes,
                    ],
                    'ms'        => (int) round((microtime(true) - $t0) * 1000),
                    'saved'     => $srcBytes > 0 ? round((1 - $fullBytes / $srcBytes) * 100) : 0,
                    'notUpscaled' => $srcW <= $target,
                ];

                if ($thumbPath !== null && $thumbDim !== null) {
                    $trel      = $folder . '/' . basename($thumbPath);
                    $item['thumb'] = [
                        'url'   => imgUrl($trel),
                        'path'  => $trel,
                        'name'  => basename($thumbPath),
                        'w'     => $thumbDim[0], 'h' => $thumbDim[1],
                        'bytes' => is_file($thumbPath) ? (int) filesize($thumbPath) : 0,
                    ];
                }

                // 封面模式直接把能粘的 frontmatter 行给出来
                if ($mode === 'cover') {
                    $item['frontmatter'] = 'image: ' . $url;
                }

                $results[] = $item;
            } finally {
                imagedestroy($src);
                if ($tmpFull !== null && is_file($tmpFull)) {
                    @unlink($tmpFull);
                }
            }
        } catch (Throwable $e) {
            $results[] = [
                'ok'     => false,
                'folder' => $folder !== '' ? $folder : $origName,
                'name'   => $origName,
                'error'  => $e->getMessage(),
            ];
        }
    }

    if ($results === []) {
        jsonOut(['ok' => false, 'error' => '没解析出任何文件：字段名应为 files[]，且文件不能是 0 字节']);
    }
    if ($overflowed) {
        $results[] = ['ok' => false, 'folder' => '…', 'name' => '', 'error' => '一次最多 ' . MAX_FILES . ' 张，多余的已忽略'];
    }

    jsonOut(['ok' => true, 'results' => $results, 'groups' => scanImages()]);
}

// ============================================================
// 删除
// ============================================================

function apiDelete(): never
{
    $rel = (string) ($_POST['path'] ?? '');
    $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));

    if (!in_array($ext, ALLOWED_EXT, true)) {
        jsonOut(['ok' => false, 'error' => '只允许删除这些格式：' . implode('、', ALLOWED_EXT)]);
    }
    if (str_contains($rel, '..') || str_starts_with(basename($rel), '.')) {
        jsonOut(['ok' => false, 'error' => '路径不合法']);
    }

    $abs = safeJoin(dirname($rel), basename($rel));
    if ($abs === null || !is_file($abs)) {
        jsonOut(['ok' => false, 'error' => '文件不存在或不在 images/ 内'], 404);
    }

    if (!@unlink($abs)) {
        jsonOut(['ok' => false, 'error' => '删除失败：' . $rel], 500);
    }
    jsonOut(['ok' => true, 'deleted' => $rel, 'groups' => scanImages()]);
}

/**
 * 重命名。文件与文件夹走两条路，因为风险完全不同：
 *   - 改文件名安全，只是 URL 变了
 *   - 改文件夹名会连带作废图库里的所有 URL 和博客里写死的 image:，
 *     所以额外返回一份「会失效的地方」清单给界面提示
 */
function apiRename(): never
{
    $path = (string) ($_POST['path'] ?? '');
    $name = (string) ($_POST['name'] ?? '');
    $kind = (string) ($_POST['kind'] ?? 'file');

    if ($path === '') {
        jsonOut(['ok' => false, 'error' => '没说要改哪个'], 400);
    }

    try {
        $r = renameEntry($path, $name, $kind === 'folder');
    } catch (Throwable $e) {
        jsonOut(['ok' => false, 'error' => $e->getMessage()], 400);
    }

    $warn = [];
    if ($r['kind'] === 'folder') {
        $warn = [
            '图库里这个文件夹下所有图片的 URL 都变了',
            '如果博客 frontmatter 里写了 image: 指向这里，需要同步改',
            '旧 URL 不会立刻消失：Cloudflare 还在缓存，之后回源会变成 404',
            '被别处引用的正文内嵌图同样要改',
        ];
    }

    jsonOut([
        'ok'     => true,
        'renamed' => $r,
        'warn'   => $warn,
        'groups' => scanImages(),
    ]);
}

/** 新建空文件夹。用文件管理器的话，通常是「先建文件夹，再往里放东西」。 */
function apiNewFolder(): never
{
    $raw = (string) ($_POST['name'] ?? '');
    $name = sanitizeFolder($raw);
    if ($name === '') {
        jsonOut(['ok' => false, 'error' => '文件夹名不合法：只允许字母、数字、点、下划线、连字符，且要以字母或数字开头'], 400);
    }
    if (is_dir((string) resolveFolder($name))) {
        jsonOut(['ok' => false, 'error' => '已经有这个文件夹了'], 409);
    }
    if (ensureFolder($name) === null) {
        jsonOut(['ok' => false, 'error' => '建不出来，检查 images/ 是否可写'], 500);
    }
    jsonOut(['ok' => true, 'folder' => $name, 'groups' => scanImages()]);
}

function apiDelFolder(): never
{
    $folder = sanitizeFolder((string) ($_POST['folder'] ?? ''));
    if ($folder === '') {
        jsonOut(['ok' => false, 'error' => '文件夹名不合法']);
    }
    $dir = resolveFolder($folder);
    if ($dir === null || !is_dir($dir)) {
        jsonOut(['ok' => false, 'error' => '文件夹不存在'], 404);
    }

    // 只删空文件夹，避免误删一整篇文章的图
    $left = array_values(array_diff(scandir($dir) ?: [], ['.', '..']));
    if ($left !== []) {
        jsonOut(['ok' => false, 'error' => '文件夹里还有 ' . count($left) . ' 个文件，先删完或手动处理'], 409);
    }
    if (!@rmdir($dir)) {
        jsonOut(['ok' => false, 'error' => '删除失败'], 500);
    }
    jsonOut(['ok' => true, 'deleted' => $folder, 'groups' => scanImages()]);
}

// ============================================================
// 改口令
// ============================================================

/**
 * 改口令。安全上的三个要点：
 *  - 必须先验当前口令。这个接口在登录态下才可达，但 cookie 被偷走后光有 cookie
 *    就够改口令的话，等于攻击者能永久接管图床。
 *  - 新哈希与新 hmac 一起落盘。hmac 一换，其它设备上的已登录 cookie 立刻失效，
 *    「我改口令了但手机上还能进」这种半吊子状态不会出现。
 *  - 写的是 secret.php 而不是 lib.php，写坏了图床照样能用初始口令进。
 */
function apiChangePassword(): never
{
    $cur     = (string) ($_POST['current'] ?? '');
    $next    = (string) ($_POST['next'] ?? '');
    $confirm = (string) ($_POST['confirm'] ?? '');

    $sec = secret();

    // secret.php 坏掉时 secret() 已经重新生成了，所以这里**不能**拒。
    // 以前是「坏了就让你先用初始口令进来，改一次修复」；现在没有「初始口令」
    // 这个概念了 —— 重建后的那个就是当前口令，而改口令恰恰是修复手段。
    // 在这儿拦住它等于把唯一的出路堵死，主人就再也进不去了。

    if (!password_verify($cur, $sec['hash'])) {
        // 和登录失败一样拖一下，堵本地暴力猜
        sleep(2);
        jsonOut(['ok' => false, 'error' => '当前口令不对'], 401);
    }

    $err = checkNewPassword($next, $confirm);
    if ($err !== null) {
        jsonOut(['ok' => false, 'error' => $err]);
    }

    // 明确用 bcrypt，别让 PASSWORD_DEFAULT 漂到 argon2 —— 免费主机的内存限制扛不住 argon2
    $hash = password_hash($next, PASSWORD_BCRYPT, ['cost' => 12]);
    if (!is_string($hash) || !str_starts_with($hash, '$2y$')) {
        jsonOut(['ok' => false, 'error' => '生成 bcrypt 哈希失败'], 500);
    }

    $hmac = bin2hex(random_bytes(32));

    if (!saveSecret($hash, $hmac)) {
        jsonOut([
            'ok'    => false,
            'error' => '写不了 ' . secretPath() . '：图床根目录不可写。'
                     . '可以先在 cPanel 里把权限改成 755，或改用手动改 lib.php 的方式。',
        ], 500);
    }

    // 让本请求后续逻辑用上新值
    secretSet(['hash' => $hash, 'hmac' => $hmac, 'mustChange' => false]);

    // 口令换掉了，明文那份没有存在理由了 —— 留着就等于长期摊开一个
    // 「所有曾经拿到过初始口令的人」都能用的后门
    forgetInitialPassword();

    // 重新签发 cookie：旧 cookie 是用旧 hmac 签的，不换的话当前浏览器会被自己踢出去
    $exp     = time() + COOKIE_TTL;
    $payload = b64u(json_encode(['exp' => $exp], JSON_THROW_ON_ERROR));
    $sig     = hash_hmac('sha256', $payload . '|' . $exp, $hmac);
    $cookie  = $payload . '.' . $sig;
    sendAuthCookie($cookie);

    // CSRF 必须用「刚签发的这个 cookie」来算。
    // csrfToken() 默认读 $_COOKIE —— 那是请求里带来的**旧** cookie（用旧 hmac 签的），
    // 而 hmac 已经换了，算出来的 token 与新 cookie 不匹配，前端下一次写操作必定 403。
    // 这个 bug 很隐蔽：改口令「成功」了，但紧接着的所有操作都失败。
    //
    // 传参要传**纯值**（$_COOKIE[name] 就是纯值，不带 "name=" 前缀），
    // 格式必须和 csrfToken() 默认分支完全一致，否则算出来的还是另一个 token。
    jsonOut([
        'ok'     => true,
        'csrf'   => csrfToken($cookie),
        'kicked' => true,           // 其它设备上的登录已失效
    ]);
}

// ============================================================
// 页面
// ============================================================

function pageHead(string $title): string
{
    $csrf = csrfToken();
    $esc  = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
    // 样式抽到 theme.css —— 值抄自 personal-site/src/styles/theme.ts，两边要一起改
    $cssVer = (string) @filemtime(THEME_CSS);

    return <<<HTML
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="theme-color" content="#eef2ff">
<link rel="icon" href="{$esc(SITE_FAVICON)}" type="image/png">
<title>{$title}</title>
<link rel="stylesheet" href="theme.css?v={$cssVer}">
<style>
  /* 只放本页特有的东西，共用样式在 theme.css */
  /* 模式 + 质量：拖拽区下面一行。模式吃掉剩余宽度，质量固定窄一点。
     两栏用 stretch + 控件 flex:1，是为了保证两个框一样高。
     之前靠 align-items:flex-end 对齐底边，但 select 在 Chrome 下比同 padding 的
     number 天然高 2px（去掉上下箭头之后仍然如此），于是顶边错开 2px，很显眼。
     改成两栏等高、控件各自撑满剩下的空间，就不依赖任何浏览器的固有高度了。 */
  .mode-row { display:flex; gap:12px; align-items:stretch; margin-top:16px; }
  .mode-field { flex:1; min-width:0; display:flex; flex-direction:column; }
  .mode-field.mode-q { flex:0 0 92px; }
  .mode-field > select, .mode-field > input { flex:1; min-height:0; }
  /* 封面模式下质量用不上，整个字段藏起来（连同它占的 92px） */
  .mode-field[hidden] { display:none; }
  /* 数字框去掉上下箭头：92px 宽放不下、会挤掉数字 */
  #q { -moz-appearance:textfield; appearance:textfield; }
  #q::-webkit-outer-spin-button, #q::-webkit-inner-spin-button { -webkit-appearance:none; margin:0; }
  #barNote { min-height:1.2em; }

  /* 反爬拦截横幅 */
  #blocked {
    display:flex; align-items:center; gap:14px; flex-wrap:wrap;
    margin-top:16px; padding:14px 18px;
    background:#fffbeb; border:1px solid rgba(180,83,9,.35);
    border-radius:var(--radius-card); color:#78350f; font-size:13.5px; line-height:1.7;
  }
  #blocked[hidden] { display:none; }
  #blocked > div { flex:1; min-width:240px; }
  #blocked .btn { flex-shrink:0; padding:9px 18px; }
  @media (max-width: 860px) {
    .fm-main { grid-template-columns: 1fr; }
    .fm-side { border-right:0; border-bottom:1px solid var(--line); max-height:200px; }
  }
</style>
</head>
<body>
HTML;
}

function pageFoot(string $extra = ''): string
{
    return "\n" . $extra . "\n</body>\n</html>\n";
}

/**
 * 登录页。版式照抄 LoginCard：头像圆环 + 24px/800 主标题 + 13px 副标题
 * + 14px 圆角输入框 + indigo 渐变大按钮。
 */
function renderLogin(string $error = '', int $code = 200): never
{
    http_response_code($code);
    header('Cache-Control: no-store');
    header('X-Robots-Tag: noindex, nofollow');
    $e       = htmlspecialchars($error, ENT_QUOTES, 'UTF-8');
    $icon    = htmlspecialchars(SITE_FAVICON, ENT_QUOTES, 'UTF-8');
    $product = htmlspecialchars(SITE_PRODUCT, ENT_QUOTES, 'UTF-8');

    // 首次部署生成的那个口令。显示在这一页而不是根路径的静态登录页上：
    // 根路径那个是站点正门，谁路过都能看见；而 /index.php 得特意访问。
    // 明文同时存了一份在 private/initial-password.txt，改完口令就删掉。
    $sec = secret();
    $initPw = $sec['mustChange'] ? initialPassword() : null;

    echo pageHead(SITE_TITLE);
    echo <<<HTML
<div class="login-wrap">
  <div class="login-card">
    <div class="login-brand">
      <img src="{$icon}" alt="Fuhao574">
    </div>
    <h1 class="login-headline">{$product}</h1>
    <p class="login-sub">需要口令才能进入</p>
HTML;
    if ($initPw !== null) {
        $pwHtml = htmlspecialchars($initPw, ENT_QUOTES, 'UTF-8');
        $why = $sec['broken']
            ? '原来的 private/secret.php 读不出来，已经重新生成一个。'
            : '这是首次部署自动生成的随机口令。';
        echo <<<HTML
    <div class="login-init">
      <p class="login-init-t">{$why}<b>用下面的口令进来，然后立刻在右下角改掉。</b></p>
      <div class="copy-row">
        <code class="login-init-pw" id="initPw">{$pwHtml}</code>
        <button class="copy-btn" type="button" data-c="{$pwHtml}">复制</button>
      </div>
      <p class="login-init-n">在改掉之前，知道这个口令的人进得来，所以别放太久。
         改完这一行会消失。</p>
    </div>
HTML;
    }
    echo <<<HTML
    <!-- 表单 POST 到 index.php?do=login（无 ajax 参数），失败时服务端直接重渲染本页并带上错误。
         JS 正常时会先 whoami 探测自动跳走，走到这里说明 JS 没生效。 -->
    <form method="post" action="index.php?do=login" autocomplete="off">
      <label for="pw">口令</label>
      <input id="pw" name="password" type="password" placeholder="请输入口令"
             autocomplete="current-password" autofocus required>
      <button class="btn" type="submit">进入</button>
    </form>
HTML;
    if ($e !== '') {
        echo '<p class="err" style="margin:14px 0 0;text-align:center">' . $e . '</p>';
    }
    // 注意：这段在 heredoc 里，PHP 标签不会生效，用 {$foot}
    $foot = SITE_NAME . ' · ' . SITE_TAGLINE;
    echo <<<HTML
  </div>
  <p class="login-foot">{$foot}</p>
</div>
HTML;
    echo pageFoot();
    exit;
}

function renderDashboard(): void
{
    $csrf   = csrfToken();
    $groups = scanImages();
    $gd     = gd_info();
    $folders = array_values(array_filter(array_map(
        static fn(array $g): string => $g['folder'],
        $groups
    ), static fn(string $f): bool => $f !== '(根目录)'));

    header('Cache-Control: no-store');
    header('X-Robots-Tag: noindex, nofollow');
    $sec  = secret();
    echo pageHead(SITE_TITLE);
    ?>
<div class="wrap">
  <h1><?= SITE_PRODUCT ?></h1>
  <p class="sub">
    图片落在 <code>images/</code> 下，一个博文一个文件夹，文件夹名 = 文章 slug。
    命名沿用博客现有约定。<a href="?do=logout" style="float:right">登出</a>
  </p>

  <div class="card">
    <div id="drop">
      <div class="big">把图片拖到这里，或点击选择</div>
      <div class="hint">PNG / JPEG / WebP / GIF / AVIF，可多选，一次最多 <?= MAX_FILES ?> 张</div>
    </div>
    <input type="file" id="picker" multiple accept="image/png,image/jpeg,image/webp,image/gif,image/avif">
    <div id="files"></div>

    <!-- 模式和质量放在拖拽区下面、上传按钮上面。
         原来它们单独占一张卡（上面那张），但一张卡只放两个控件、
         再跟两行说明文字，视觉上比真正要干的活（拖拽 + 上传）还重。
         合到一张卡里之后，从上到下就是：放图 → 调参数 → 上传。 -->
    <div class="mode-row">
      <div class="mode-field">
        <label for="mode">模式</label>
        <select id="mode">
          <option value="normal">普通图片 — 单个 WebP</option>
          <option value="cover">封面 — 双尺寸（1672 + 320），文件名锁定为 &lt;文件夹&gt;-cover</option>
        </select>
      </div>
      <div id="normalBox" class="mode-field mode-q">
        <label for="q">质量</label>
        <input id="q" type="number" min="30" max="100" value="<?= NORMAL_Q ?>">
      </div>
    </div>
    <p class="meta" id="modeHint" style="margin:10px 0 0"></p>

    <div class="row" style="margin-top:16px">
      <button class="btn" id="go" disabled>开始上传</button>
      <span class="meta" id="status"></span>
      <span class="meta" style="margin-left:auto" id="counter"></span>
    </div>

    <div id="bar">
      <div class="bar-top">
        <span class="meta" id="barNote"></span>
        <span id="barPct">0%</span>
      </div>
      <div class="bar-track"><div class="bar-fill" id="barFill"></div></div>
      <p class="meta" style="margin:8px 0 0">
        进度条只覆盖「把图送到服务器」。跑满之后是 GD 转码，那段在服务器上跑，
        本页面收不到进度事件 —— 所以会显示「服务器转码中…」而不是停住不动。
      </p>
    </div>

    <datalist id="folderList">
      <?php foreach ($folders as $f): ?><option value="<?= htmlspecialchars($f, ENT_QUOTES) ?>"><?php endforeach; ?>
    </datalist>
  </div>

  <div id="results"></div>

  <!-- 反爬拦截提示。默认隐藏，出现条件见下面 readJson() 的说明。 -->
  <div id="blocked" hidden>
    <div>
      <b>被服务器的反爬拦下了。</b>
      这台主机的反爬会对请求返回一段带脚本的验证页，而浏览器只在<b>顶层导航</b>时执行它 ——
      页内 fetch 拿到的只是一段文本，所以提交会失败。刷新一次让浏览器过验证即可。
    </div>
    <button class="btn" id="blockedReload" type="button">刷新页面</button>
  </div>

  <?php
  // 图库本体（renderGallery）自带标题栏、工具条和状态栏。
  // 原来这里还包了一层「图库 + 计数 + 刷新」的 .card，那份计数和刷新按钮
  // 和文件管理器的完全重复，而且 <div id="gallery"> 已经没人往里填了。
  echo renderGallery($groups);
  ?>

  <details>
    <summary>改口令</summary>
    <?php if ($sec['broken']): ?>
      <p class="meta err" style="margin:10px 0 0">
        <code><?= htmlspecialchars(secretPath(), ENT_QUOTES) ?></code> 原来读不出来（可能被写坏或截断），
        已经重新生成一个新口令并覆盖了它。下面填「当前口令」时用新生成的那个。
      </p>
    <?php elseif ($sec['mustChange']): ?>
      <p class="meta err" style="margin:10px 0 0">
        当前还是首次部署自动生成的那个口令。在改掉之前，知道它的人能进来看图、删图，
        所以下面的「改口令」要先填一次。
      </p>
    <?php else: ?>
      <p class="meta" style="margin:10px 0 0">
        当前口令来自 <code><?= htmlspecialchars(secretPath(), ENT_QUOTES) ?></code>。
        改口令会重新生成登录签名密钥，所以其它设备上的已登录状态会一起失效。
      </p>
    <?php endif; ?>

    <form id="pwForm" style="max-width:420px;margin-top:14px">
      <label for="pwCur">当前口令</label>
      <input id="pwCur" type="password" autocomplete="current-password" required>
      <label for="pwNew" style="margin-top:12px">新口令</label>
      <input id="pwNew" type="password" autocomplete="new-password" required
             placeholder="不设复杂度要求，别超过 72 字节">
      <label for="pwNew2" style="margin-top:12px">再输一次</label>
      <input id="pwNew2" type="password" autocomplete="new-password" required>
      <div class="row" style="margin-top:14px">
        <button class="btn" id="pwGo" type="submit">改口令</button>
        <span class="meta" id="pwMsg"></span>
      </div>
    </form>
  </details>

  <details>
    <summary>服务器环境（排查用）</summary>
    <table>
      <tr><th>PHP</th><td><?= htmlspecialchars(PHP_VERSION) ?> · <?= htmlspecialchars((string) ($_SERVER['SERVER_SOFTWARE'] ?? '?')) ?></td></tr>
      <tr><th>GD</th><td><?= htmlspecialchars((string) ($gd['GD Version'] ?? '?')) ?> · WebP <?= !empty($gd['WebP Support']) ? '支持' : '<b style="color:var(--sig-red)">不支持</b>' ?></td></tr>
      <tr><th>upload_max_filesize</th><td><?= htmlspecialchars(iniHuman('upload_max_filesize')) ?></td></tr>
      <tr><th>post_max_size</th><td><?= htmlspecialchars(iniHuman('post_max_size')) ?></td></tr>
      <tr><th>max_execution_time</th><td><?= htmlspecialchars((string) ini_get('max_execution_time')) ?> 秒</td></tr>
      <tr><th>max_file_uploads</th><td><?= htmlspecialchars((string) ini_get('max_file_uploads')) ?></td></tr>
      <tr><th>images/ 可写</th><td><?= is_writable(IMAGES) ? '是' : '<b style="color:var(--sig-red)">否</b>' ?></td></tr>
      <tr><th>固定参数</th><td>封面 <?= COVER_W ?>px q<?= COVER_Q ?> + <?= COVER_THUMB ?>px q<?= COVER_THUMB_Q ?> · 正文图固定 <?= NORMAL_MAX_W ?>px（q 可调，默认 <?= NORMAL_Q ?>）</td></tr>
    </table>
  </details>

  <div class="modal" id="modal" onclick="this.classList.remove('on')">
    <img id="modalImg" alt="">
  </div>

  <div class="fm-menu" id="fmMenu"></div>
  <?php
  echo pageFoot(scriptBlock($csrf, $groups));
}

/**
 * 图库（Windows 文件管理器样式）。
 *
 * 服务端只渲染外壳（侧栏树 / 工具条 / 状态栏），内容区留空。
 * 之后的内容 —— 过滤、换视图、排序、选中、右键 —— 全在前端的 fmRender() 里做，
 * 图库数据已经随首屏一起下发了，不为「切个视图」再往返一次服务器。
 * 所以这里不要再写一份内容区的 PHP 渲染，两套会漂开。
 */
function renderGallery(array $groups): string
{
    $e = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');

    $total = array_sum(array_column($groups, 'bytes'));
    $count = array_sum(array_column($groups, 'count'));

    // 左侧树**不在这里渲染**。原来这里有一份 PHP 版，fmLoad() 里又有一份 JS 版，
    // 两份必然漂开 —— 这次加「文件夹右键菜单」时就漂了一次：data-folder 只加到了
    // JS 那份，结果首屏（还没点过任何按钮、树还是服务端渲染的）右键文件夹
    // 什么菜单都不出，切一次文件夹之后才正常。
    //
    // 现在只留 fmLoad() 里那一份，首屏直接调 fmLoad() 建树。
    // 同类教训：上一轮的 fmItemsHtml() 也是服务端一份、前端一份。

    // 顶部：面包屑 + 视图切换
    $bar = '<div class="fm-bar">'
        . '<div class="fm-crumb" id="fmCrumb"></div>'
        . '<div class="fm-tools">'
        . '<div class="fm-views">'
        . '<button data-view="icons" aria-pressed="true">大图标</button>'
        . '<button data-view="list" aria-pressed="false">详细信息</button>'
        . '</div>'
        . '<button class="ghost" id="fmNew">新建文件夹</button>'
        . '<button class="ghost" id="fmRefresh">刷新</button>'
        . '<button class="ghost" id="fmBackup" title="把images/ 整个打成 zip 下载到本地">打包下载</button>'
        . '</div></div>'
        // 选中操作条。默认隐藏，一有选中就冒出来 ——
        // 多选功能之前只有 Ctrl+点 和 Delete 键，没入口也没提示，
        // 等于藏起来了。「有时候需要批量删图」是明确需求，不能靠用户自己猜。
        . '<div class="fm-sel" id="fmSel" hidden>'
        . '<span class="fm-sel-n" id="fmSelN"></span>'
        . '<button class="ghost" id="fmSelAll">全选</button>'
        . '<button class="ghost" id="fmSelInv">反选</button>'
        . '<button class="ghost" id="fmSelNone">取消选择</button>'
        . '<button class="danger" id="fmSelDel">删除所选</button>'
        . '<span class="fm-sel-tip">Ctrl 点选多个 · Shift 连选 · Delete 删</span>'
        . '</div>';

    $content = $groups === []
        ? '<p class="fm-empty">images/ 还是空的。上面拖几张图进来就有了。</p>'
        : '';

    $status = '<div class="fm-status">'
        . '<span id="fmCount">' . count($groups) . ' 个文件夹 · ' . $count . ' 个项目 · ' . fmtBytes($total) . '</span>'
        . '<button class="url" id="fmUrl" title="点击复制"></button>'
        . '</div>';

    return '<div class="fm">'
        . $bar
        . '<div class="fm-main"><div class="fm-side" id="fmSide"></div>'
        . '<div class="fm-content" id="fmContent">' . $content . '</div></div>'
        . $status
        . '</div>';
}

// 内容区的渲染（网格 / 列表、排序、选中态）全在前端的 fmRender() 里。
// 这里刻意不再写一份 PHP 版本：图库数据本来就随首屏一起下发了，
// 两套渲染器迟早会漂开 —— 之前 cellHtml() 和前端的 cell() 就是这么不同步的，
// 症状是「首屏长一个样，上传后长另一个样」。

function scriptBlock(string $csrf, array $groups): string
{
    $csrfJs = json_encode($csrf, JSON_UNESCAPED_SLASHES);
    /**
     * 换行常量，两个字符：反斜杠 + n。
     *
     * **必须用单引号。** heredoc 的转义规则只作用于**字面文本**，
     * 插进来的变量值是原样拼进去的、不再被扫描一遍。所以单引号里的
     * '\n'（反斜杠+n）会原样出现在 JS 源码里，JS 再把它解成换行。
     *
     * 别写成 json_encode("\n") —— 那是**四个**字符：" \ n "，
     * 插进 confirm('…？{$nl}只有空文件夹能删。') 就变成
     *     confirm('…？"\n"只有空文件夹能删。')
     * 换行是对的，但每行两侧多出一对双引号，弹窗里就变成
     *     删除 3 个文件？"
     *     a.webp"
     * 一眼看着像坏了。
     */
    $nl = '\n';
    // heredoc 只认花括号插值（{$var}），短回显标签会原样出现在 JS 里，
    // 整段 script 直接 SyntaxError —— 而 php -l 和 node --check 都发现不了。
    $normalW = (string) NORMAL_MAX_W;
    $normalQ = (string) NORMAL_Q;

    /**
     * 注意：这段 JS 放在 heredoc 里，而 heredoc 的转义规则跟双引号字符串一样，
     * 所以**字面写的** \n 会被展开成真实换行符。于是
     * confirm('…？\n只有空文件夹能删。') 会变成
     *     confirm('…？
     * 只有空文件夹能删。')
     * 字符串被劈开 → 整段 script SyntaxError → 页面上所有交互全死，
     * 而且报错只在浏览器控制台里，php -l 和 node --check 都发现不了。
     *
     * 所以 heredoc 字面文本里的换行一律用 {$nl}。
     */
    $groupsJs = json_encode(
        array_map(
            static function (array $g): array {
                return [
                    'folder' => $g['folder'],
                    'slug'   => $g['slug'],
                    'bytes'  => $g['bytes'],
                    'count'  => $g['count'],
                    'cover'  => $g['cover'],
                    'files'  => $g['files'],
                ];
            },
            $groups
        ),
        JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
    );
    return <<<HTML
<script>
// 改口令后 hmac 变了，CSRF token 也会变，所以必须是 let 而不是 const
let CSRF = {$csrfJs};
const picked = [];
const filesEl = document.getElementById('files');
const dropEl  = document.getElementById('drop');
const picker  = document.getElementById('picker');
const goBtn   = document.getElementById('go');
const statusEl= document.getElementById('status');
const resEl   = document.getElementById('results');
const modeEl  = document.getElementById('mode');
const normalBox = document.getElementById('normalBox');
const barEl      = document.getElementById('bar');
const barFillEl  = document.getElementById('barFill');
const barPctEl   = document.getElementById('barPct');
const barNoteEl  = document.getElementById('barNote');

const esc = s => String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const kb = b => b < 1048576 ? Math.round(b/1024) + ' KB' : (b/1048576).toFixed(2) + ' MB';
const sleep = ms => new Promise(r => setTimeout(r, ms));
// 只用来显示一句话，让提示里的数字跟 lib.php 的常量一致，不会写歪
const NORMAL_MAX_W_JS = {$normalW};
const NORMAL_Q_JS = {$normalQ};

function hint(){
  const cover = modeEl.value === 'cover';
  // 封面模式用不上质量，整个字段（含它占的 92px）一起收掉
  normalBox.hidden = cover;
  // 说明压到一行。以前是两行长句，现在空间紧了，而且「82 够用」这种结论
  // 写一次就够 —— 推导过程在 lib.php 的 NORMAL_Q 注释里。
  document.getElementById('modeHint').innerHTML = cover
    ? '文件名锁定为 <code>&lt;文件夹&gt;-cover.webp</code>，另出一张 <code>-320</code> 缩略图（1672 q88 + 320 q80）。frontmatter 里 <code>image:</code> 引的就是它。'
    : '只出一张 WebP，宽度固定 <code>' + NORMAL_MAX_W_JS + 'px</code>（超过就缩，不足不放大）。质量 ' + NORMAL_Q_JS + ' 就够，再调高只涨体积。';
  if (cover) { picked.forEach(p => p.lock = true); }
  else { picked.forEach(p => p.lock = false); }
  render();
}
modeEl.addEventListener('change', hint);
hint();

function addFiles(list){
  const cover = modeEl.value === 'cover';
  for (const f of list) {
    if (!f.type.startsWith('image/')) continue;
    const base = f.name.replace(/\.[^.]+$/, '');
    picked.push({ file: f, folder: base, name: base, lock: cover });
  }
  render();
}

function render(){
  const cover = modeEl.value === 'cover';
  filesEl.innerHTML = '';
  picked.forEach((p, i) => {
    const d = document.createElement('div');
    d.className = 'file';
    d.innerHTML =
      '<div><div class="nm">' + esc(p.file.name) + '</div><div class="sz">' + kb(p.file.size) + '</div></div>' +
      '<div><label>文件夹</label><input list="folderList" spellcheck="false"></div>' +
      '<div><label>文件名' + (cover ? '（封面模式锁定）' : '') + '</label><input spellcheck="false"' + (cover ? ' disabled' : '') + '></div>' +
      '<button class="ghost danger">移除</button>';
    const fi = d.querySelectorAll('input')[0];
    const ni = d.querySelectorAll('input')[1];
    fi.value = p.folder; ni.value = p.name;
    fi.addEventListener('input', () => { picked[i].folder = fi.value; });
    if (!cover) ni.addEventListener('input', () => { picked[i].name = ni.value; });
    d.querySelector('button').addEventListener('click', () => { picked.splice(i,1); render(); });
    filesEl.appendChild(d);
  });
  goBtn.disabled = picked.length === 0;
  document.getElementById('counter').textContent = picked.length ? picked.length + ' 张待传' : '';
}

dropEl.addEventListener('click', () => picker.click());
picker.addEventListener('change', () => { addFiles(picker.files); picker.value = ''; });
['dragenter','dragover'].forEach(e => dropEl.addEventListener(e, ev => { ev.preventDefault(); dropEl.classList.add('hot'); }));
['dragleave','drop'].forEach(e => dropEl.addEventListener(e, ev => { ev.preventDefault(); dropEl.classList.remove('hot'); }));
dropEl.addEventListener('drop', e => addFiles(e.dataTransfer.files));

/**
 * 读一个 JSON 响应，并把「被反爬拦了」跟「服务器报错了」区分开。
 *
 * 这台免费主机自带反爬：命中规则时它不返回 403，而是返回一段 200 的 HTML，
 * 里面引一个 aes.js，脚本算出 cookie 然后 location.href 跳走。
 *
 * 关键在于：浏览器只在**顶层导航**时执行响应里的脚本，fetch() 拿到的那段
 * HTML 永远只是文本。于是 r.json() 抛一句
 *     Unexpected token '<', "<html><bo..." is not valid JSON
 * 用户完全看不懂，而且**重试也没用** —— 挑战脚本跳转用的是 GET，
 * 被挑战的 POST 请求体已经丢了。唯一出路是识别出来、让用户刷新页面。
 *
 * 这个识别放在一处，api() 和上传的 XHR 都走它 —— 之前两处各自 r.json()，
 * 出了同样的错、也是同样的看不懂。
 */
class BlockedError extends Error {
  constructor() { super('被反爬拦下'); this.blocked = true; }
}

function showBlocked() {
  const el = document.getElementById('blocked');
  if (el) el.hidden = false;
}
document.getElementById('blockedReload')
  .addEventListener('click', () => location.reload());

/** 判断一段文本是不是反爬挑战页。只在「本来该是 JSON 却不是」的时候才调。 */
function looksBlocked(text) {
  return typeof text === 'string'
    && text.length < 40000
    && /<script/i.test(text)
    && /aes\.js|document\.cookie|location\.href/i.test(text);
}

async function readJson(r) {
  const t = await r.text();
  const head = t.trimStart();
  if (head.charAt(0) !== '{' && head.charAt(0) !== '[') {
    if (looksBlocked(t)) { showBlocked(); throw new BlockedError(); }
    throw new Error('服务器返回的不是 JSON（HTTP ' + r.status + '）：' + t.slice(0, 120));
  }
  try {
    return JSON.parse(t);
  } catch (e) {
    throw new Error('响应不是合法 JSON：' + t.slice(0, 120));
  }
}

async function api(do_, payload){
  const fd = new FormData();
  fd.append('do', do_);
  fd.append('csrf', CSRF);
  for (const k in payload) fd.append(k, payload[k]);
  const r = await fetch(location.pathname, { method:'POST', body: fd, headers:{'X-CSRF': CSRF} });
  return readJson(r);
}

// 改口令
const pwForm = document.getElementById('pwForm');
if (pwForm) {
  const pwCur = document.getElementById('pwCur');
  const pwNew = document.getElementById('pwNew');
  const pwNew2 = document.getElementById('pwNew2');
  const pwGo = document.getElementById('pwGo');
  const pwMsg = document.getElementById('pwMsg');

  pwForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (pwNew.value !== pwNew2.value) {
      pwMsg.className = 'meta err';
      pwMsg.textContent = '两次输入不一致';
      return;
    }
    pwGo.disabled = true;
    pwMsg.className = 'meta';
    pwMsg.textContent = '处理中…';
    try {
      const j = await api('api:changepw', { current: pwCur.value, next: pwNew.value, confirm: pwNew2.value });
      if (!j.ok) {
        pwMsg.className = 'meta err';
        pwMsg.textContent = j.error || '失败';
        pwGo.disabled = false;
        return;
      }
      // 服务端换了签名密钥，CSRF token 也随之改变，这里必须同步换掉，
      // 否则后续任何写操作都会开始报 403。
      if (j.csrf) CSRF = j.csrf;
      pwCur.value = pwNew.value = pwNew2.value = '';
      pwMsg.className = 'meta';
      pwMsg.textContent = j.kicked ? '已改。其它设备上的登录已失效。' : '已改。';
      // 提示条会变淡，避免用户以为没生效
      setTimeout(() => { pwMsg.textContent = ''; }, 6000);
    } catch (e) {
      pwMsg.className = 'meta err';
      pwMsg.textContent = e.message;
      pwGo.disabled = false;
    }
  });
}

// 传大图时 fetch() 不给上传进度，看着像卡死；XHR 的 upload.onprogress 才有。
// 另外转码发生在服务器端，进度条跑满后会有一段空白，所以单独给「服务器处理中」的提示。
const UPLOAD_TIMEOUT_MS = 180000;

function uploadWithProgress(fd, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', location.pathname, true);
    xhr.setRequestHeader('X-CSRF', CSRF);
    xhr.timeout = UPLOAD_TIMEOUT_MS;

    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(e.loaded / e.total, e.loaded, e.total);
    };
    xhr.onload = () => {
      // 注意：反爬拦截返回的是 **200 + HTML**，不是错误码。所以光看 status === 200
      // 放行不出去 —— 上传十几张图的中途被拦，文件已经传出去了、服务器却没收到，
      // 界面上只剩一句看不懂的「响应不是合法 JSON」。所以走和 api() 一样的识别。
      if (xhr.status !== 200) {
        reject(new Error('HTTP ' + xhr.status + (xhr.responseText ? '：' + xhr.responseText.slice(0, 200) : '')));
        return;
      }
      const t = xhr.responseText || '';
      if (t.trimStart().charAt(0) !== '{') {
        if (looksBlocked(t)) { showBlocked(); reject(new BlockedError()); }
        else reject(new Error('服务器返回的不是 JSON：' + t.slice(0, 200)));
        return;
      }
      try { resolve(JSON.parse(t)); }
      catch { reject(new Error('响应不是合法 JSON：' + t.slice(0, 200))); }
    };
    xhr.onerror = () => reject(new Error('网络错误，上传中断'));
    xhr.ontimeout = () => reject(new Error('超过 ' + (UPLOAD_TIMEOUT_MS / 1000) + ' 秒还没完成，已中止'));
    xhr.onabort = () => reject(new Error('已取消'));
    xhr.send(fd);
  });
}

function drawProgress(pct, note) {
  const p = Math.max(0, Math.min(100, pct));
  barEl.classList.add('on');
  barFillEl.style.width = p.toFixed(1) + '%';
  barPctEl.textContent = p.toFixed(0) + '%';
  barNoteEl.textContent = note || '';
  bar.lastPct = p;
}

// done / bad 只是「结果配色」，不该在下一轮上传开始时留在 DOM 上。
// （之前 done 是设在 drawProgress 之后的，重复上传会带着上一轮的成功态。）
function resetProgress() {
  barEl.classList.remove('done', 'bad');
  barFillEl.style.width = '0%';
  barPctEl.textContent = '0%';
  barNoteEl.textContent = '';
}

goBtn.addEventListener('click', async () => {
  if (!picked.length) return;
  goBtn.disabled = true;
  goBtn.textContent = '上传中…';
  resEl.innerHTML = '';
  resetProgress();

  const fd = new FormData();
  fd.append('do', 'api:upload');
  fd.append('csrf', CSRF);
  fd.append('mode', modeEl.value);
  // 不再传 maxW —— 宽度是 NORMAL_MAX_W 常量（2560），见 lib.php 里那段为什么是 2560 的说明
  fd.append('q', document.getElementById('q').value);
  const totalBytes = picked.reduce((a, p) => a + p.file.size, 0);
  picked.forEach(p => {
    fd.append('files[]', p.file, p.file.name);
    fd.append('folders[]', p.folder);
    fd.append('names[]', p.name);
  });

  const t0 = Date.now();
  let sentDone = false;

  try {
    const j = await uploadWithProgress(fd, (frac, loaded, total) => {
      sentDone = true;
      const secs = (Date.now() - t0) / 1000;
      const speed = secs > 0.3 ? (loaded / 1048576) / secs : 0;
      // 大文件会连发很多 progress 事件，按 0.5% 粒度节流，避免刷爆 DOM
      const pct = frac * 100;
      const last = bar.lastPct || 0;
      if (pct < 100 && pct - last < 0.5) return;
      drawProgress(
        pct,
        '上传中 ' + kb(loaded) + ' / ' + kb(total)
          + (speed > 0.01 ? '  ·  ' + speed.toFixed(2) + ' MB/s' : '')
      );
    });

    // 传输结束，服务器还在 GD 转码 —— 这段没有进度事件，明确告诉用户
    if (sentDone) {
      const spent = ((Date.now() - t0) / 1000).toFixed(1);
      drawProgress(100, '已上传 ' + spent + ' 秒，服务器转码中…');
      statusEl.textContent = '服务器正在转码…';
      await sleep(30); // 让转码中的文案有机会被渲染出来再返回
    }

    if (!j.ok) {
      resEl.innerHTML = '<div class="card bad"><div class="err">' + esc(j.error || '失败') + '</div></div>'
        + envTable(j.env);
      statusEl.textContent = '失败';
      barNoteEl.textContent = '失败：' + (j.error || '');
      return;
    }

    const okN = j.results.filter(x => x.ok).length;
    const badN = showFailures(j.results);
    if (j.groups) fmLoad(j.groups);
    statusEl.textContent = resultSummary(j.results, t0);
    drawProgress(100, okN + ' 张成功'
      + (badN ? '，' + badN + ' 张失败（见下方）' : '')
      + '  ·  ' + kb(totalBytes) + ' → WebP');
    barEl.classList.add('done');
    if (okN) { picked.length = 0; render(); }
  } catch (e) {
    resEl.innerHTML = '<div class="card bad"><div class="err">' + esc(e.message) + '</div></div>'
      + '<p class="meta">如果是「超过 N 秒」，多半是主机 CPU 紧张或上传体积太大，可以先只传一张试试。</p>';
    statusEl.textContent = '失败';
    drawProgress(0, '失败：' + e.message);
    barEl.classList.add('bad');
  } finally {
    goBtn.disabled = picked.length === 0;
    goBtn.textContent = '开始上传';
  }
});

function envTable(env){
  if (!env) return '';
  let h = '<div class="card"><div class="meta">服务器当时的限制</div><table>';
  for (const k in env) h += '<tr><th>' + esc(k) + '</th><td>' + esc(env[k]) + '</td></tr>';
  return h + '</table></div>';
}



/**
 * 上传结果：**成功的不出卡片**，只把失败的列出来。
 *
 * 之前每张成功的图都渲染一张大卡：文件名、URL、frontmatter、还有一张原尺寸预览。
 * 一轮传十几张就是十几屏，把下面的图库整个顶走，而那些信息在图库里右键就能拿到
 * （复制链接 / 复制 frontmatter 行）。用户明确要求去掉，所以这里只留真正需要
 * 处理的东西 —— 失败项。
 */
function showFailures(rs) {
  resEl.innerHTML = '';
  const bad = rs.filter(r => !r.ok);
  if (!bad.length) return 0;
  const box = document.createElement('div');
  box.className = 'card bad';
  box.innerHTML = '<h2>' + bad.length + ' 张失败</h2>'
    + bad.map(r => '<div class="err">'
        + esc(((r.folder ? r.folder + ' / ' : '') + (r.name || '')) || '（未命名）') + '：'
        + esc(r.error || '未知错误') + '</div>').join('');
  resEl.appendChild(box);
  return bad.length;
}

/**
 * 成功信息压成一行，放进状态栏。
 *
 * 原来这些散在一堆卡片里：源尺寸 → 输出尺寸、耗时、省了多少、是不是复用了旧文件。
 * 卡片去掉之后至少把「省了多少」和总耗时留住 —— 唯一还需要瞄一眼的数就是它
 * （判断这个质量档位值不值，全看省了多少）。
 */
function resultSummary(rs, t0) {
  const ok = rs.filter(r => r.ok);
  const secs = ((Date.now() - t0) / 1000).toFixed(1);
  if (!ok.length) return '全部失败';
  let s = '完成 ' + ok.length + ' / ' + rs.length + '  ·  ' + secs + ' 秒';
  const srcB = ok.reduce((a, r) => a + (r.source ? r.source.bytes : 0), 0);
  const outB = ok.reduce((a, r) => a + (r.file ? r.file.bytes : 0), 0);
  if (srcB > 0) {
    s += '  ·  ' + kb(srcB) + ' → ' + kb(outB)
       + '（省 ' + Math.round((1 - outB / srcB) * 100) + '%）';
  }
  const cover = ok.filter(r => r.mode === 'cover').length;
  if (cover) s += '  ·  ' + cover + ' 张封面（另出 -320 缩略图）';
  const anim = ok.filter(r => r.animated).length;
  // 动图原样保存，一个字节都没压 —— 不说清楚的话，「省 0%」看着像 bug
  if (anim) s += '  ·  ' + anim + ' 张动图原样保存（没转码，压了就没动画了）';
  const reused = ok.filter(r => r.identical).length;
  if (reused) s += '  ·  ' + reused + ' 张内容相同，复用旧文件';
  return s;
}

// 复制。flashEl 传了就闪一下「已复制 ✓」，1.4 秒后还原。
function copyText(raw, flashEl){
  const done = () => {
    if (!flashEl) return;
    const o = flashEl.dataset.o || flashEl.textContent;
    flashEl.dataset.o = o;
    flashEl.textContent = '已复制 ✓';
    setTimeout(() => { flashEl.textContent = flashEl.dataset.o; }, 1400);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(raw).then(done, () => window.prompt('复制', raw));
  } else {
    // http 场景 clipboard API 不可用，退回 execCommand
    const ta = document.createElement('textarea');
    ta.value = raw;
    ta.style.cssText = 'position:fixed;left:-9999px';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    ok ? done() : window.prompt('复制', raw);
  }
}

/* 这里原来有个 bindCopy()：给 .url 值块和 .copy-btn 按钮统一挂复制事件，
   服务端渲染的那一批 copy-row 全靠它。
   成功的上传结果卡片去掉之后，页面上再没有任何地方生成 .copy-row /
   .copy-btn 了（图库的 URL 复制走的是右键菜单），所以整块删掉 ——
   留着的话它会绑到 #fmUrl 上，而 #fmUrl 本来就有自己的 click 处理，
   于是点一下复制两次。 */

/* ============================================================
   图库 —— 文件管理器
   ============================================================
   数据已经全量在浏览器里了，所以「切文件夹 / 切视图 / 选中 / 右键」
   全在前端做，不再往返服务器。只有增删改才调接口。
   ============================================================ */

const FM = {
  groups: {$groupsJs},  // 服务端随首屏下发的图库数据
  cur: '',              // 当前文件夹 slug，'' = 所有图片
  view: 'icons',        // icons | list
  sort: 'name',         // name | size | mtime
  sel: new Set(),       // 选中的 path 集合
  anchor: '',           // Shift 连选的起点（Windows 资源管理器那套）
};

// 视图偏好记在 localStorage，下次打开保持
try {
  const v = localStorage.getItem('imghost.view');
  if (v === 'icons' || v === 'list') FM.view = v;
} catch (e) {}

function fmFiles() {
  // 当前视图下应该显示哪些文件
  let files;
  if (FM.cur === '') {
    files = [];
    FM.groups.forEach(g => g.files.forEach(f => { f.isCover = !!g.cover && f.path === g.cover.path; files.push(f); }));
  } else {
    const g = FM.groups.find(x => x.slug === FM.cur);
    files = g ? g.files.map(f => Object.assign({}, f, { isCover: !!g.cover && f.path === g.cover.path })) : [];
  }

  const dir = FM.cur !== '' ? FM.cur + '/' : '';
  files.sort((a, b) => {
    if (FM.sort === 'size')  return b.bytes - a.bytes || a.name.localeCompare(b.name);
    if (FM.sort === 'mtime') return b.mtime - a.mtime || a.name.localeCompare(b.name);
    // 默认按名称；封面排最前，因为它通常是这一组的主角
    if (!!a.isCover !== !!b.isCover) return a.isCover ? -1 : 1;
    return a.name.localeCompare(b.name, 'zh', { numeric: true });
  });
  files.forEach(f => { f.dir = dir; });
  return files;
}

function fmRender() {
  const content = document.getElementById('fmContent');
  const files = fmFiles();

  if (files.length === 0) {
    content.innerHTML = '<p class="fm-empty">'
      + (FM.groups.length === 0 ? 'images/ 还是空的。上面拖几张图进来就有了。'
                                : '这个文件夹里还没有图片。')
      + '</p>';
  } else if (FM.view === 'list') {
    let h = '<table class="fm-list"><thead><tr>'
      + '<th data-sort="name">名称</th>'
      + '<th class="c-num" data-sort="size">大小</th>'
      + '<th data-sort="mtime">修改时间</th><th>URL</th>'
      + '</tr></thead><tbody>';
    files.forEach(f => {
      h += '<tr data-path="' + esc(f.path) + '"' + (FM.sel.has(f.path) ? ' aria-selected="true"' : '') + '>'
        + '<td><div class="c-name"><img src="' + esc(f.url) + '" alt="" loading="lazy">'
        + '<span>' + esc(f.name) + '</span>' + (f.isCover ? ' <span class="badge">封面</span>' : '')
        + '</div></td>'
        + '<td class="c-num">' + kb(f.bytes) + '</td>'
        + '<td>' + new Date(f.mtime * 1000).toISOString().slice(0, 16).replace('T', ' ') + '</td>'
        + '<td class="c-url">' + esc(f.url) + '</td></tr>';
    });
    content.innerHTML = h + '</tbody></table>';
  } else {
    let h = '<div class="fm-grid">';
    files.forEach(f => {
      h += '<div class="fm-item" data-path="' + esc(f.path) + '"'
        + (FM.sel.has(f.path) ? ' aria-selected="true"' : '') + '>'
        + '<img class="thumb" src="' + esc(f.url) + '" alt="" loading="lazy" onclick="zoom(this.src)">'
        + '<div class="nm">' + esc(f.name) + '</div>'
        + '<div class="sub"><span>' + kb(f.bytes) + '</span>'
        + (f.isCover ? '<span class="badge">封面</span>' : '') + '</div>'
        + '</div>';
    });
    content.innerHTML = h + '</div>';
  }

  // 面包屑：所有图片 > 文件夹名
  document.getElementById('fmCrumb').innerHTML =
      '<button data-goto="">所有图片</button>'
    + (FM.cur ? '<span class="sep">›</span><span class="cur">' + esc(FM.cur) + '</span>' : '');

  // 左侧树高亮
  document.querySelectorAll('#fmSide button').forEach(b => {
    b.setAttribute('aria-current', b.dataset.goto === FM.cur ? 'true' : 'false');
  });

  // 视图按钮
  document.querySelectorAll('.fm-views button').forEach(b => {
    b.setAttribute('aria-pressed', b.dataset.view === FM.view ? 'true' : 'false');
  });

  // 状态栏
  const total = files.reduce((a, f) => a + f.bytes, 0);
  const n = FM.sel.size;
  document.getElementById('fmCount').textContent =
      files.length + ' 个项目 · ' + kb(total)
    + (n ? ' · 已选 ' + n + ' 个' : '')
    + (FM.cur ? '' : '（' + FM.groups.length + ' 个文件夹）');

  // 选中操作条。有选中才出现 —— 全选 / 反选 / 取消 / 删除 四个按钮
  const selBar = document.getElementById('fmSel');
  selBar.hidden = n === 0;
  if (n) {
    const all = files.length;
    document.getElementById('fmSelN').textContent = n === all
      ? '已选中全部 ' + all + ' 个'
      : '已选 ' + n + ' / ' + all + ' 个';
  }

  const urlEl = document.getElementById('fmUrl');
  if (n === 1) {
    const f = files.find(x => FM.sel.has(x.path));
    if (f) { urlEl.textContent = f.url; urlEl.dataset.c = f.url; urlEl.style.display = ''; return; }
  }
  urlEl.textContent = '';
  urlEl.style.display = 'none';
}

/** 服务端给了新数据后调用 */
function fmLoad(groups) {
  FM.groups = groups || FM.groups || [];
  // 当前文件夹可能已经被删了，退回「所有图片」
  if (FM.cur && !FM.groups.some(g => g.slug === FM.cur)) FM.cur = '';
  // 选中项可能已经不存在了
  const alive = new Set();
  FM.groups.forEach(g => g.files.forEach(f => alive.add(f.path)));
  Array.from(FM.sel).forEach(p => { if (!alive.has(p)) FM.sel.delete(p); });

  // 左侧树
  const allIco = '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">'
    + '<rect x="3" y="4" width="7" height="7" rx="1.5"/><rect x="14" y="4" width="7" height="7" rx="1.5"/>'
    + '<rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>';
  const fIco = '<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8">'
    + '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7z"/></svg>';

  let side = '<h4>位置</h4><button data-goto="">' + allIco
    + '<span class="nm">所有图片</span><span class="ct">'
    + FM.groups.reduce((a, g) => a + g.count, 0) + '</span></button>';
  if (FM.groups.length) {
    side += '<h4>文件夹</h4>';
    FM.groups.forEach(g => {
      // data-folder 供右键菜单认：这个按钮管的是文件夹本身
      // （data-goto 是给左键点击跳转用的，两件事分开标记）
      side += '<button data-goto="' + esc(g.slug) + '" data-folder="' + esc(g.slug) + '">' + fIco
        + '<span class="nm">' + esc(g.folder) + '</span>'
        + '<span class="ct">' + g.count + '</span></button>';
    });
  }
  document.getElementById('fmSide').innerHTML = side;

  fmRender();
}

/* ---------- 选中 ---------- */
/**
 * 三种点法，和 Windows 资源管理器一致：
 *   点一下        = 只选这一个
 *   Ctrl / ⌘ + 点 = 加一个 / 减一个
 *   Shift + 点    = 从上次点的位置连选到这里
 *
 * Shift 连选靠 FM.anchor 记起点。必须按**当前排序后的顺序**取区间，
 * 而不能按 path 集合的插入顺序 —— 排序一变（点表头、按大小排）区间就乱了，
 * 会出现「选中的东西在界面上不连续」的结果，看着像 bug。
 */
function fmSelect(path, e) {
  const mod = !!(e && (e.ctrlKey || e.metaKey));
  const shift = !!(e && e.shiftKey);

  if (shift && FM.anchor) {
    const files = fmFiles().map(f => f.path);
    const a = files.indexOf(FM.anchor);
    const b = files.indexOf(path);
    if (a >= 0 && b >= 0) {
      const [lo, hi] = a < b ? [a, b] : [b, a];
      // 连选是「替换」而不是「追加」——不按 Ctrl+Shift 时 Shift 的语义就是选一段
      if (!mod) FM.sel.clear();
      for (let i = lo; i <= hi; i++) FM.sel.add(files[i]);
      return fmRender();
    }
    // 起点已经不在列表里（换了文件夹 / 排序变了）：退化成普通单击，别静默不动
  }

  if (!mod) FM.sel.clear();
  if (mod && FM.sel.has(path)) FM.sel.delete(path);
  else FM.sel.add(path);
  FM.anchor = path;
  fmRender();
}

/* ---------- 右键菜单 ---------- */
/**
 * 两套菜单。
 *
 * 文件夹的重命名/删除放在**左侧树的文件夹上**右键，不再塞进图片的右键菜单。
 * 之前那样做有两个毛病：一是得先「进」那个文件夹才看得到这一项，而进文件夹
 * 之后又只能右键某张图片才找得到 —— 删文件夹这件事的触发点跟图片没关系，
 * 挂在图片上纯属绕远路；二是空文件夹里一张图都没有，那就永远右键不出来，
 * 唯一能删它的办法是先往里塞一张图再删、再把那张删掉。
 */
const FM_MENU_FILE = [
  { k: 'url',    t: '复制链接' },
  { k: 'fm',     t: '复制 frontmatter 行' },
  { k: 'md',     t: '复制 Markdown' },
  { sep: true },
  { k: 'rename', t: '重命名' },
  { sep: true },
  { k: 'del',    t: '删除', danger: true },
];

const FM_MENU_FOLDER = [
  { k: 'fopen',   t: '在此打开' },
  { k: 'frename', t: '重命名文件夹' },
  { sep: true },
  { k: 'fdeldir', t: '删除文件夹', danger: true },
];

function menuItemsHtml(items) {
  let h = '';
  items.forEach(it => {
    if (it.sep) { h += '<div class="sep"></div>'; return; }
    h += '<button data-k="' + it.k + '"' + (it.danger ? ' class="danger"' : '') + '>'
       + esc(it.t) + '</button>';
  });
  return h;
}

/** 摆位 + 防溢出（贴边时翻到另一侧）。两套菜单共用这一段。 */
function fmShowMenu(x, y, html, kind, target) {
  const m = document.getElementById('fmMenu');
  m.innerHTML = html;
  m.classList.add('on');
  const r = m.getBoundingClientRect();
  m.style.left = Math.min(x, window.innerWidth - r.width - 8) + 'px';
  m.style.top  = Math.min(y, window.innerHeight - r.height - 8) + 'px';
  m.dataset.kind = kind;
  m.dataset.target = target || '';
}

function fmMenu(x, y, path) {
  if (!fmFiles().find(v => v.path === path)) return fmHideMenu();
  fmShowMenu(x, y, menuItemsHtml(FM_MENU_FILE), 'file', path);
}

function fmFolderMenu(x, y, slug) {
  fmShowMenu(x, y, menuItemsHtml(FM_MENU_FOLDER), 'folder', slug);
}

function fmHideMenu() { document.getElementById('fmMenu').classList.remove('on'); }

/** 文件菜单的动作 */
async function fmFileAction(k, path) {
  const f = fmFiles().find(v => v.path === path);
  if (!f) return;

  if (k === 'url') return copyText(f.url);
  if (k === 'fm')  return copyText('image: ' + f.url);
  if (k === 'md')  return copyText('![](' + f.url + ')');

  if (k === 'rename') {
    const stem = f.name.replace(/\.[^.]+$/, '');
    const tip = '改成什么名字？{$nl}扩展名 ' + f.ext + ' 会自动保留{$nl}只允许字母、数字、点、下划线、连字符';
    const n = prompt(tip, stem);
    if (n === null) return;
    const j = await api('api:rename', { path: f.path, name: n, kind: 'file' });
    if (!j.ok) return alert(j.error);
    // 改名后保持选中。用服务端回的 path（相对 images/），
    // 别拿 to（纯文件名）去拼 —— 拼错了选中态就悄悄消失了。
    FM.sel.clear();
    if (j.renamed && j.renamed.path) FM.sel.add(j.renamed.path);
    return fmLoad(j.groups);
  }

  if (k === 'del') {
    // 右键多选时删的是整个选中集，不只是右键的那一个 ——
    // 和 Windows 的行为一致（右键已选中的项 = 对选中集操作）
    if (FM.sel.has(path) && FM.sel.size > 1) return fmDelSel();
    if (!confirm('删除 ' + f.name + ' ？{$nl}删了就找不回来了。{$nl}（Cloudflare 可能还会继续发旧图一阵子）')) return;
    const j = await api('api:delete', { path: f.path });
    if (!j.ok) return alert(j.error);
    FM.sel.clear();
    return fmLoad(j.groups);
  }
}

/** 文件夹菜单的动作。slug 是文件夹名（相对 images/）。 */
async function fmFolderAction(k, slug) {
  if (!slug) return;
  const g = FM.groups.find(x => x.slug === slug);

  if (k === 'fopen') {
    FM.cur = slug;
    FM.sel.clear();
    return fmRender();
  }

  if (k === 'frename') {
    const tip = '改成什么名字？{$nl}注意：这个文件夹里所有图片的 URL 都会跟着变，{$nl}博客 frontmatter 里写了 image: 指向这里的话要同步改{$nl}{$nl}只允许字母、数字、点、下划线、连字符';
    const n = prompt(tip, g ? g.folder : slug);
    if (n === null) return;
    const j = await api('api:rename', { path: slug, name: n, kind: 'folder' });
    if (!j.ok) return alert(j.error);
    // 正站在这个文件夹里的话要跟着改名走。不改的话 fmLoad 会发现当前文件夹
    // 没了、把你悄悄踢回「所有图片」—— 改个名却连位置都丢了。
    const to = j.renamed && j.renamed.path ? j.renamed.path : slug;
    if (FM.cur === slug) FM.cur = to;
    return fmLoad(j.groups);
  }

  if (k === 'fdeldir') {
    const n = g ? g.count : 0;
    const body = n ? '里面有 ' + n + ' 个文件，得先删空才能删这个文件夹。' : '（空文件夹，可以直接删）';
    if (!confirm('删除文件夹 ' + (g ? g.folder : slug) + ' ？{$nl}' + body)) return;
    const j = await api('api:delfolder', { folder: slug });
    if (!j.ok) return alert(j.error);
    if (FM.cur === slug) FM.cur = '';
    FM.sel.clear();
    return fmLoad(j.groups);
  }
}

document.addEventListener('click', async (ev) => {
  // 菜单里点了某个动作
  const b = ev.target.closest('#fmMenu button');
  if (b) {
    const m = document.getElementById('fmMenu');
    const kind = m.dataset.kind, target = m.dataset.target, k = b.dataset.k;
    fmHideMenu();
    return kind === 'folder' ? fmFolderAction(k, target) : fmFileAction(k, target);
  }

  // 点空白处：关菜单 + 清选中
  //
  // 排除清单里必须有 .fm-sel —— 选中操作条上的「全选 / 反选 / 取消」也在这
  // 个 click 里。少了它的话，点「全选」会先选中、紧接着被这里清掉，
  // 表现为「按了没反应」。
  if (!ev.target.closest('#fmMenu')) fmHideMenu();
  if (!ev.target.closest('.fm-item, .fm-list tbody tr, .fm-tools, .fm-crumb, .fm-side, .fm-sel')) {
    if (FM.sel.size) { FM.sel.clear(); fmRender(); }
  }
});

document.addEventListener('contextmenu', (ev) => {
  // 左侧树的文件夹：给文件夹菜单（重命名 / 删除）
  const fb = ev.target.closest('#fmSide button[data-folder]');
  if (fb) {
    ev.preventDefault();
    return fmFolderMenu(ev.clientX, ev.clientY, fb.dataset.folder);
  }
  // 内容区的图片 / 文件行：给文件菜单
  const item = ev.target.closest('.fm-item, .fm-list tbody tr');
  if (!item) return fmHideMenu();
  ev.preventDefault();
  const path = item.dataset.path;
  // 右键未选中的项 → 先把选中换成它
  if (!FM.sel.has(path)) { FM.sel.clear(); FM.sel.add(path); fmRender(); }
  fmMenu(ev.clientX, ev.clientY, path);
});

/**
 * 删掉当前的选中集。
 *
 * 逐个删而不是发一个批量请求：批量接口没有，而逐个删时中途失败
 * 只会弹一条报错，剩下的照删 —— 状态不会错乱。
 * 全程最后统一 fmLoad 一次，免得删一张图就整个重画一次。
 */
async function fmDelSel() {
  const paths = Array.from(FM.sel);
  if (!paths.length) return;
  const names = paths.map(p => p.split('/').pop());
  if (!confirm('删除 ' + paths.length + ' 个文件？{$nl}' + names.join('{$nl}') + '{$nl}{$nl}删了就找不回来了。{$nl}（Cloudflare 可能还会继续发旧图一阵子）')) return;
  let groups = null, bad = 0;
  for (const p of paths) {
    const j = await api('api:delete', { path: p });
    if (j.ok && j.groups) groups = j.groups;
    else { bad++; alert(p.split('/').pop() + '：' + (j.error || '删除失败')); }
  }
  FM.sel.clear();
  if (groups) fmLoad(groups);
  else fmRender();
  if (bad) alert('有 ' + bad + ' 个文件没删掉，见上面的提示。');
}

document.addEventListener('keydown', async (ev) => {
  if (ev.key === 'Escape') { fmHideMenu(); return; }

  // 输入框里不抢快捷键
  const tag = document.activeElement && document.activeElement.tagName;
  if (/INPUT|TEXTAREA|SELECT/.test(tag) || (document.activeElement && document.activeElement.isContentEditable)) return;
  if (ev.ctrlKey || ev.metaKey || ev.altKey) {
    // Ctrl+A 全选（Windows 习惯）。没有这条的话「全选」只能一个个 Ctrl+点
    if ((ev.ctrlKey || ev.metaKey) && (ev.key === 'a' || ev.key === 'A')) {
      const files = fmFiles();
      if (!files.length) return;
      ev.preventDefault();
      FM.sel.clear();
      files.forEach(f => FM.sel.add(f.path));
      fmRender();
    }
    return;
  }

  // 文件管理器习惯：Delete 删选中项
  if (ev.key === 'Delete' || ev.key === 'Backspace') {
    if (!FM.sel.size) return;
    ev.preventDefault();
    return fmDelSel();
  }
});

async function refresh(){ const j = await api('api:list', {}); if (j.ok) fmLoad(j.groups); }

// 左侧树 / 面包屑 切文件夹
document.addEventListener('click', (ev) => {
  const g = ev.target.closest('[data-goto]');
  if (!g) return;
  FM.cur = g.dataset.goto;
  FM.sel.clear();
  fmRender();
});

// 视图切换
document.addEventListener('click', (ev) => {
  const v = ev.target.closest('[data-view]');
  if (!v) return;
  FM.view = v.dataset.view;
  try { localStorage.setItem('imghost.view', FM.view); } catch (e) {}
  fmRender();
});

// 表头排序
document.addEventListener('click', (ev) => {
  const th = ev.target.closest('[data-sort]');
  if (!th) return;
  FM.sort = th.dataset.sort;
  fmRender();
});

// 内容区点选
document.getElementById('fmContent').addEventListener('click', (ev) => {
  const item = ev.target.closest('.fm-item, .fm-list tbody tr');
  if (!item) return;
  fmSelect(item.dataset.path, ev);
});

document.getElementById('fmNew').addEventListener('click', async () => {
  const n = prompt('新建文件夹名{$nl}通常就是新文章的 slug，比如 my-new-post');
  if (!n) return;
  const j = await api('api:newfolder', { name: n });
  if (!j.ok) return alert(j.error);
  FM.cur = j.folder;
  return fmLoad(j.groups);
});

document.getElementById('fmRefresh').addEventListener('click', refresh);

/* ---------- 打包下载全量备份 ----------
   免费主机说撂挑子就撂挑子，图片全在这台机器上，所以这个按钮是刚需不是功能。
   点击流程刻意做成「先问体量，再决定要不要下载」：
   点下去就开一个几百兆的请求，用户是没有退路的。先报「多少个文件、多大」，
   有风险提示才让他确认。体量正常时直接开始，不多问一句。 */
document.getElementById('fmBackup').addEventListener('click', async (ev) => {
  const btn = ev.currentTarget;
  const statusEl = document.getElementById('status');
  const keep = statusEl.textContent;
  btn.disabled = true;
  statusEl.textContent = '正在算体量…';
  try {
    const j = await api('api:backupinfo', {});
    if (!j.ok) return alert(j.error || '算不出来');
    if (!j.files) {
      statusEl.textContent = keep;
      return alert('images/ 下还没有文件，没什么可打包的。');
    }
    // 有警告才确认。平时这一步是直通的，「一键」才是一键。
    // 消息先拼好再 confirm —— confirm 的参数不能跨行（heredoc 的老规矩）。
    if (j.warnings.length) {
      const msg = '要打包 ' + j.files + ' 个文件，共 ' + kb(j.bytes) + '。{$nl}{$nl}'
        + j.warnings.join('{$nl}{$nl}') + '{$nl}{$nl}现在开始下载？';
      if (!confirm(msg)) { statusEl.textContent = keep; return; }
    }
    statusEl.textContent = '正在下载 ' + j.files + ' 个文件 / ' + kb(j.bytes) + '…';
    // 顶层导航而不是 fetch + Blob：几百 MB 用 Blob 接的话浏览器内存里会
    // 存两份，而且这台的挑战页只在导航时才会被执行。
    location.href = 'index.php?do=download';
  } catch (e) {
    statusEl.textContent = keep;
    alert(e.message);
  }
  // 下载是导航，页面会离开，所以这里不用恢复按钮状态；
  // 万一浏览器把它当成同页跳转，用户还能再点一次。
  btn.disabled = false;
});

/* ---------- 选中操作条 ---------- */
document.getElementById('fmSelAll').addEventListener('click', () => {
  FM.sel.clear();
  fmFiles().forEach(f => FM.sel.add(f.path));
  fmRender();
});

document.getElementById('fmSelInv').addEventListener('click', () => {
  // 反选：集合的对称差
  const next = new Set();
  fmFiles().forEach(f => { if (!FM.sel.has(f.path)) next.add(f.path); });
  FM.sel = next;
  fmRender();
});

document.getElementById('fmSelNone').addEventListener('click', () => {
  FM.sel.clear();
  fmRender();
});

document.getElementById('fmSelDel').addEventListener('click', () => fmDelSel());

// 状态栏的 URL 点击复制
document.getElementById('fmUrl').addEventListener('click', (ev) => {
  if (ev.currentTarget.dataset.c) copyText(ev.currentTarget.dataset.c, ev.currentTarget);
});

function zoom(src){ document.getElementById('modalImg').src = src; document.getElementById('modal').classList.add('on'); }

// 首屏：建左侧树 + 渲染内容区。
// 走 fmLoad（而不是 fmRender）是因为左侧树现在**只有** fmLoad 里那一份实现，
// 服务端不再预渲染它了 —— 见 renderGallery 里那段说明。
// 不传参数：fmLoad(undefined) 会保留已经随页面下发给 FM.groups 的数据。
fmLoad();
</script>
HTML;
}