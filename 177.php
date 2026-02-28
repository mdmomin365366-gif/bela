<?php
/**
 * Professional PHP File Manager
 * Single-file implementation with authentication and security features
 * Version: 2.0 - Dark Terminal Edition
 */

define('FM_PASSWORD', 'bela');
define('FM_SESSION_TIMEOUT', 3600);
define('FM_ROOT_PATH', dirname(__FILE__));
define('FM_SHOW_HIDDEN', false);
define('FM_ALLOWED_EXTENSIONS', 'txt,php,html,css,js,json,xml,htaccess,md,log,sql,csv,ini,conf,yml,yaml,hpp,cpp,c,h,py,sh,bat');
define('FM_MAX_UPLOAD_SIZE_MB', 50);
define('FM_ALLOW_SYSTEM_WIDE', true);

class SecurityHelper {
    public static function generateCSRFToken() {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
    public static function validateCSRFToken($token) {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
    public static function sanitizePath($path) {
        $path = str_replace(['../', '..\\'], '', $path);
        $path = preg_replace('#/+#', '/', $path);
        return $path;
    }
    public static function isPathAllowed($path) {
        if (!FM_ALLOW_SYSTEM_WIDE) {
            $rootPath = realpath(FM_ROOT_PATH);
            $checkPath = realpath($path);
            if ($checkPath === false || strpos($checkPath, $rootPath) !== 0) return false;
        }
        return true;
    }
    public static function setSecurityHeaders() {
        header('X-Frame-Options: SAMEORIGIN');
        header('X-Content-Type-Options: nosniff');
        header('X-XSS-Protection: 1; mode=block');
    }
}

class FileManagerAuth {
    public static function startSession() {
        if (session_status() === PHP_SESSION_NONE) {
            ini_set('session.cookie_httponly', 1);
            ini_set('session.use_only_cookies', 1);
            session_start();
        }
        if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > FM_SESSION_TIMEOUT)) {
            self::logout();
            return false;
        }
        $_SESSION['last_activity'] = time();
        return true;
    }
    public static function isAuthenticated() {
        return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
    }
    public static function login($password) {
        if ($password === FM_PASSWORD) {
            $_SESSION['authenticated'] = true;
            $_SESSION['login_time'] = time();
            $_SESSION['last_activity'] = time();
            return true;
        }
        return false;
    }
    public static function logout() {
        session_unset();
        session_destroy();
    }
}

function formatSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, 2) . ' ' . $units[$pow];
}

function getFileIcon($isDir, $filename) {
    if ($isDir) return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>';
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $icons = [
        'php' => '<svg viewBox="0 0 24 24" fill="none" stroke="#a78bfa" stroke-width="2" width="16" height="16"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        'html' => '<svg viewBox="0 0 24 24" fill="none" stroke="#fb923c" stroke-width="2" width="16" height="16"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        'css' => '<svg viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="10"/><path d="M8 12h8"/></svg>',
        'js' => '<svg viewBox="0 0 24 24" fill="none" stroke="#fbbf24" stroke-width="2" width="16" height="16"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>',
        'json' => '<svg viewBox="0 0 24 24" fill="none" stroke="#34d399" stroke-width="2" width="16" height="16"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>',
        'sql' => '<svg viewBox="0 0 24 24" fill="none" stroke="#f472b6" stroke-width="2" width="16" height="16"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>',
    ];
    $default = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>';
    return $icons[$ext] ?? $default;
}

function isEditableFile($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $allowed = explode(',', FM_ALLOWED_EXTENSIONS);
    return in_array($ext, $allowed);
}

function getUserDirectories() {
    $dirs = [];
    if (is_dir('/home') && is_readable('/home')) {
        $scan = @scandir('/home');
        if ($scan) {
            foreach ($scan as $item) {
                if ($item !== '.' && $item !== '..' && is_dir('/home/' . $item)) {
                    $dirs[] = '/home/' . $item;
                }
            }
        }
    }
    return $dirs;
}

SecurityHelper::setSecurityHeaders();
FileManagerAuth::startSession();

if (isset($_GET['logout'])) {
    FileManagerAuth::logout();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

if (!FileManagerAuth::isAuthenticated()) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        if (FileManagerAuth::login($_POST['password'])) {
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $loginError = 'Access denied. Invalid credentials.';
        }
    }
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FM :: Auth</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&display=swap');
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'JetBrains Mono', 'Courier New', monospace;
            background: #0a0a0f;
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }
        body::before {
            content: '';
            position: fixed;
            inset: 0;
            background: 
                repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,255,100,0.015) 2px, rgba(0,255,100,0.015) 4px);
            pointer-events: none;
            z-index: 0;
        }
        .login-wrap {
            position: relative;
            z-index: 1;
            width: 400px;
        }
        .terminal-bar {
            background: #1a1a2e;
            border: 1px solid #00ff6420;
            border-bottom: none;
            border-radius: 8px 8px 0 0;
            padding: 10px 16px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .dot { width: 12px; height: 12px; border-radius: 50%; }
        .dot.r { background: #ff5f57; }
        .dot.y { background: #febc2e; }
        .dot.g { background: #28c840; }
        .terminal-title { color: #666; font-size: 11px; margin-left: auto; }
        .login-box {
            background: #0d0d1a;
            border: 1px solid #00ff6420;
            border-top: none;
            border-radius: 0 0 8px 8px;
            padding: 40px;
        }
        .prompt-line {
            color: #00ff64;
            font-size: 11px;
            margin-bottom: 30px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .prompt-line::before {
            content: '>';
            color: #00ff64;
            animation: blink 1s step-end infinite;
        }
        @keyframes blink { 50% { opacity: 0; } }
        h2 {
            color: #e2e8f0;
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 6px;
            letter-spacing: 2px;
            text-transform: uppercase;
        }
        .subtitle { color: #475569; font-size: 11px; margin-bottom: 30px; }
        label { display: block; color: #64748b; font-size: 11px; margin-bottom: 6px; letter-spacing: 1px; text-transform: uppercase; }
        input[type="password"] {
            width: 100%;
            padding: 12px 16px;
            background: #0a0a0f;
            border: 1px solid #1e293b;
            border-radius: 6px;
            color: #00ff64;
            font-family: inherit;
            font-size: 14px;
            letter-spacing: 3px;
            margin-bottom: 20px;
            transition: border-color 0.2s;
            outline: none;
        }
        input[type="password"]:focus { border-color: #00ff6440; box-shadow: 0 0 0 3px #00ff6410; }
        button[type="submit"] {
            width: 100%;
            padding: 12px;
            background: transparent;
            border: 1px solid #00ff6440;
            border-radius: 6px;
            color: #00ff64;
            font-family: inherit;
            font-size: 13px;
            letter-spacing: 2px;
            text-transform: uppercase;
            cursor: pointer;
            transition: all 0.2s;
        }
        button[type="submit"]:hover {
            background: #00ff6410;
            border-color: #00ff6480;
            box-shadow: 0 0 20px #00ff6420;
        }
        .error {
            background: #1a0a0a;
            border: 1px solid #ff444440;
            color: #ff6b6b;
            padding: 10px 14px;
            border-radius: 6px;
            font-size: 12px;
            margin-bottom: 16px;
        }
        .error::before { content: '✗ '; }
    </style>
</head>
<body>
    <div class="login-wrap">
        <div class="terminal-bar">
            <div class="dot r"></div>
            <div class="dot y"></div>
            <div class="dot g"></div>
            <span class="terminal-title">file-manager — auth</span>
        </div>
        <div class="login-box">
            <div class="prompt-line">authentication required</div>
            <h2>File Manager</h2>
            <p class="subtitle">Enter credentials to continue</p>
            <?php if (isset($loginError)): ?>
                <div class="error"><?php echo htmlspecialchars($loginError); ?></div>
            <?php endif; ?>
            <form method="POST">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••" required autofocus>
                <button type="submit">Authenticate →</button>
            </form>
        </div>
    </div>
</body>
</html>
    <?php
    exit;
}

$currentPath = FM_ROOT_PATH;
$message = '';
$messageType = '';

if (isset($_GET['path'])) {
    $requestedPath = SecurityHelper::sanitizePath($_GET['path']);
    if ($requestedPath[0] === '/') {
        $checkPath = $requestedPath;
    } else {
        $checkPath = FM_ROOT_PATH . '/' . $requestedPath;
    }
    if (is_dir($checkPath) && SecurityHelper::isPathAllowed($checkPath)) {
        $currentPath = realpath($checkPath);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !SecurityHelper::validateCSRFToken($_POST['csrf_token'])) {
        $message = 'Security token validation failed';
        $messageType = 'error';
    } else {
        if (isset($_FILES['upload_file'])) {
            $uploadPath = $currentPath . '/' . basename($_FILES['upload_file']['name']);
            $maxSize = FM_MAX_UPLOAD_SIZE_MB * 1024 * 1024;
            if ($_FILES['upload_file']['size'] > $maxSize) {
                $message = 'File size exceeds maximum allowed size';
                $messageType = 'error';
            } elseif (move_uploaded_file($_FILES['upload_file']['tmp_name'], $uploadPath)) {
                $message = 'File uploaded successfully';
                $messageType = 'success';
            } else {
                $message = 'Failed to upload file';
                $messageType = 'error';
            }
        }
        if (isset($_POST['create_folder'])) {
            $folderName = basename($_POST['folder_name']);
            $newFolder = $currentPath . '/' . $folderName;
            if (mkdir($newFolder, 0755)) {
                $message = 'Folder created successfully';
                $messageType = 'success';
            } else {
                $message = 'Failed to create folder';
                $messageType = 'error';
            }
        }
        if (isset($_POST['create_file'])) {
            $fileName = basename($_POST['file_name']);
            $newFile = $currentPath . '/' . $fileName;
            if (file_put_contents($newFile, '') !== false) {
                $message = 'File created successfully';
                $messageType = 'success';
            } else {
                $message = 'Failed to create file';
                $messageType = 'error';
            }
        }
        if (isset($_POST['rename_item'])) {
            $oldName = $currentPath . '/' . basename($_POST['old_name']);
            $newName = $currentPath . '/' . basename($_POST['new_name']);
            if (rename($oldName, $newName)) {
                $message = 'Item renamed successfully';
                $messageType = 'success';
            } else {
                $message = 'Failed to rename item';
                $messageType = 'error';
            }
        }
        if (isset($_POST['delete_item'])) {
            $itemPath = $currentPath . '/' . basename($_POST['item_name']);
            function deleteDirectory($dir) {
                if (!is_dir($dir)) return unlink($dir);
                $items = array_diff(scandir($dir), ['.', '..']);
                foreach ($items as $item) {
                    $path = $dir . '/' . $item;
                    is_dir($path) ? deleteDirectory($path) : unlink($path);
                }
                return rmdir($dir);
            }
            if (deleteDirectory($itemPath)) {
                $message = 'Item deleted successfully';
                $messageType = 'success';
            } else {
                $message = 'Failed to delete item';
                $messageType = 'error';
            }
        }
        if (isset($_POST['save_file'])) {
            $filePath = SecurityHelper::sanitizePath($_POST['file_path']);
            if (file_put_contents($filePath, $_POST['file_content']) !== false) {
                $message = 'File saved successfully';
                $messageType = 'success';
            } else {
                $message = 'Failed to save file';
                $messageType = 'error';
            }
        }
    }
}

if (isset($_GET['download'])) {
    $downloadFile = $currentPath . '/' . basename($_GET['download']);
    if (file_exists($downloadFile) && is_file($downloadFile)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($downloadFile) . '"');
        header('Content-Length: ' . filesize($downloadFile));
        readfile($downloadFile);
        exit;
    }
}

if (isset($_GET['edit'])) {
    $editFile = $currentPath . '/' . basename($_GET['edit']);
    if (file_exists($editFile) && is_file($editFile) && isEditableFile($editFile)) {
        $fileContent = file_get_contents($editFile);
        $fileSize = filesize($editFile);
        $lastModified = date('Y-m-d H:i:s', filemtime($editFile));
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edit :: <?php echo htmlspecialchars(basename($editFile)); ?></title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&display=swap');
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'JetBrains Mono', monospace; background: #080810; color: #c8d3f5; height: 100vh; display: flex; flex-direction: column; }
        .editor-header {
            background: #0d0d1a;
            border-bottom: 1px solid #1e293b;
            padding: 0;
            display: flex;
            align-items: stretch;
        }
        .tab {
            padding: 14px 24px;
            background: #080810;
            border-right: 1px solid #1e293b;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 13px;
            color: #94a3b8;
        }
        .tab .dot { width: 8px; height: 8px; background: #f59e0b; border-radius: 50%; }
        .editor-meta {
            padding: 14px 24px;
            font-size: 11px;
            color: #475569;
            display: flex;
            gap: 20px;
            align-items: center;
        }
        .editor-meta span { display: flex; align-items: center; gap: 5px; }
        .editor-meta span::before { content: '//'; color: #334155; }
        .toolbar {
            padding: 10px 20px;
            background: #0a0a15;
            border-bottom: 1px solid #1e293b;
            display: flex;
            gap: 10px;
            align-items: center;
        }
        .editor-wrap { flex: 1; display: flex; overflow: hidden; position: relative; }
        .line-numbers {
            background: #0a0a15;
            border-right: 1px solid #1e293b;
            padding: 16px 12px;
            text-align: right;
            font-size: 13px;
            color: #334155;
            user-select: none;
            min-width: 50px;
            overflow: hidden;
            line-height: 1.6;
            white-space: pre;
        }
        textarea {
            flex: 1;
            padding: 16px;
            background: #080810;
            border: none;
            color: #c8d3f5;
            font-family: inherit;
            font-size: 13px;
            line-height: 1.6;
            resize: none;
            outline: none;
            tab-size: 4;
        }
        textarea::selection { background: #00ff6420; }
        .btn {
            padding: 8px 18px;
            border-radius: 5px;
            font-family: inherit;
            font-size: 12px;
            letter-spacing: 1px;
            cursor: pointer;
            border: 1px solid transparent;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.15s;
        }
        .btn-save { background: #00ff6415; border-color: #00ff6440; color: #00ff64; }
        .btn-save:hover { background: #00ff6425; box-shadow: 0 0 12px #00ff6420; }
        .btn-back { background: transparent; border-color: #1e293b; color: #64748b; }
        .btn-back:hover { border-color: #475569; color: #94a3b8; }
        .statusbar {
            background: #0d0d1a;
            border-top: 1px solid #1e293b;
            padding: 6px 20px;
            font-size: 11px;
            color: #475569;
            display: flex;
            gap: 20px;
        }
    </style>
</head>
<body>
    <div class="editor-header">
        <div class="tab">
            <div class="dot"></div>
            <?php echo htmlspecialchars(basename($editFile)); ?>
        </div>
        <div class="editor-meta">
            <span><?php echo htmlspecialchars($editFile); ?></span>
            <span><?php echo formatSize($fileSize); ?></span>
            <span><?php echo htmlspecialchars($lastModified); ?></span>
        </div>
    </div>
    <form method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($editFile))); ?>" style="display:flex;flex-direction:column;flex:1;overflow:hidden;">
        <input type="hidden" name="csrf_token" value="<?php echo SecurityHelper::generateCSRFToken(); ?>">
        <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($editFile); ?>">
        <div class="toolbar">
            <button type="submit" name="save_file" class="btn btn-save">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
                Save
            </button>
            <a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($editFile))); ?>" class="btn btn-back">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><polyline points="15 18 9 12 15 6"/></svg>
                Back
            </a>
        </div>
        <div class="editor-wrap">
            <div class="line-numbers" id="lineNums">1</div>
            <textarea name="file_content" id="editor" spellcheck="false" onscroll="syncScroll()" oninput="updateLines()"><?php echo htmlspecialchars($fileContent); ?></textarea>
        </div>
    </form>
    <div class="statusbar">
        <span>UTF-8</span>
        <span><?php echo strtoupper(pathinfo($editFile, PATHINFO_EXTENSION)); ?></span>
        <span id="cursorPos">Ln 1, Col 1</span>
    </div>
    <script>
        const editor = document.getElementById('editor');
        const lineNums = document.getElementById('lineNums');
        function updateLines() {
            const lines = editor.value.split('\n').length;
            lineNums.textContent = Array.from({length: lines}, (_, i) => i + 1).join('\n');
        }
        function syncScroll() {
            lineNums.scrollTop = editor.scrollTop;
        }
        editor.addEventListener('keydown', e => {
            if (e.key === 'Tab') {
                e.preventDefault();
                const s = editor.selectionStart, en = editor.selectionEnd;
                editor.value = editor.value.substring(0, s) + '    ' + editor.value.substring(en);
                editor.selectionStart = editor.selectionEnd = s + 4;
            }
        });
        editor.addEventListener('keyup', e => {
            const lines = editor.value.substring(0, editor.selectionStart).split('\n');
            document.getElementById('cursorPos').textContent = `Ln ${lines.length}, Col ${lines[lines.length-1].length + 1}`;
        });
        updateLines();
    </script>
</body>
</html>
        <?php
        exit;
    }
}

$items = [];
if (is_readable($currentPath)) {
    $scanItems = scandir($currentPath);
    foreach ($scanItems as $item) {
        if ($item === '.' || (!FM_SHOW_HIDDEN && $item[0] === '.' && $item !== '..')) continue;
        $itemPath = $currentPath . '/' . $item;
        $isDir = is_dir($itemPath);
        $items[] = [
            'name' => $item,
            'is_dir' => $isDir,
            'size' => $isDir ? '—' : formatSize(filesize($itemPath)),
            'modified' => date('Y-m-d H:i:s', filemtime($itemPath)),
            'permissions' => substr(sprintf('%o', fileperms($itemPath)), -4)
        ];
    }
}

$pathParts = explode('/', str_replace('\\', '/', $currentPath));
$breadcrumb = [];
$cumulativePath = '';
foreach ($pathParts as $part) {
    if ($part === '') continue;
    $cumulativePath .= '/' . $part;
    $breadcrumb[] = ['name' => $part, 'path' => $cumulativePath];
}

$userDirs = getUserDirectories();
$sessionDuration = gmdate('H:i:s', time() - $_SESSION['login_time']);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FM :: <?php echo htmlspecialchars($currentPath); ?></title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600&display=swap');
        * { margin: 0; padding: 0; box-sizing: border-box; }
        :root {
            --bg: #080810;
            --bg2: #0d0d1a;
            --bg3: #0a0a15;
            --border: #1e293b;
            --border2: #162032;
            --text: #c8d3f5;
            --text2: #94a3b8;
            --text3: #475569;
            --text4: #334155;
            --green: #00ff64;
            --green-dim: #00ff6420;
            --green-mid: #00ff6440;
            --blue: #38bdf8;
            --purple: #a78bfa;
            --red: #ff6b6b;
            --red-dim: #ff444420;
            --yellow: #fbbf24;
        }
        body { font-family: 'JetBrains Mono', monospace; background: var(--bg); color: var(--text); min-height: 100vh; font-size: 13px; }
        
        /* Topbar */
        .topbar {
            background: var(--bg2);
            border-bottom: 1px solid var(--border);
            padding: 0 24px;
            display: flex;
            align-items: center;
            height: 48px;
            gap: 0;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        .topbar-brand {
            display: flex;
            align-items: center;
            gap: 10px;
            padding-right: 24px;
            border-right: 1px solid var(--border);
            color: var(--green);
            font-weight: 600;
            font-size: 14px;
            letter-spacing: 1px;
        }
        .topbar-brand svg { opacity: 0.8; }
        .topbar-path {
            flex: 1;
            padding: 0 20px;
            font-size: 12px;
            color: var(--text3);
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .topbar-path span { color: var(--text2); }
        .topbar-right {
            display: flex;
            align-items: center;
            gap: 16px;
            padding-left: 24px;
            border-left: 1px solid var(--border);
            font-size: 11px;
            color: var(--text3);
        }
        .topbar-right .sep { color: var(--text4); }
        .topbar-right a { color: var(--text3); text-decoration: none; transition: color 0.15s; }
        .topbar-right a:hover { color: var(--red); }

        /* Layout */
        .layout { display: flex; height: calc(100vh - 48px); overflow: hidden; }

        /* Sidebar */
        .sidebar {
            width: 220px;
            min-width: 220px;
            background: var(--bg3);
            border-right: 1px solid var(--border);
            overflow-y: auto;
            display: flex;
            flex-direction: column;
        }
        .sidebar-section { padding: 16px 0; border-bottom: 1px solid var(--border2); }
        .sidebar-label {
            padding: 0 16px 8px;
            font-size: 10px;
            color: var(--text4);
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }
        .sidebar-item {
            display: block;
            padding: 7px 16px;
            color: var(--text2);
            text-decoration: none;
            font-size: 12px;
            transition: all 0.1s;
            border-left: 2px solid transparent;
            display: flex;
            align-items: center;
            gap: 8px;
            cursor: pointer;
            background: none;
            border-top: none;
            border-right: none;
            border-bottom: none;
            width: 100%;
            font-family: inherit;
        }
        .sidebar-item:hover { background: var(--green-dim); color: var(--text); border-left-color: var(--green-mid); }
        .sidebar-item.active { background: var(--green-dim); color: var(--green); border-left-color: var(--green); }
        .sidebar-item svg { opacity: 0.6; flex-shrink: 0; }
        .sidebar-item:hover svg, .sidebar-item.active svg { opacity: 1; }

        /* Main content */
        .main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }

        /* Toolbar */
        .toolbar {
            padding: 12px 20px;
            background: var(--bg2);
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }
        .breadcrumb {
            flex: 1;
            display: flex;
            align-items: center;
            gap: 2px;
            font-size: 12px;
            color: var(--text3);
            overflow: hidden;
            min-width: 0;
        }
        .breadcrumb a { color: var(--text2); text-decoration: none; padding: 2px 4px; border-radius: 3px; transition: all 0.1s; white-space: nowrap; }
        .breadcrumb a:hover { color: var(--green); background: var(--green-dim); }
        .breadcrumb .sep { color: var(--text4); padding: 0 2px; }

        .path-form { display: flex; gap: 0; }
        .path-form input {
            padding: 7px 12px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 5px 0 0 5px;
            color: var(--text);
            font-family: inherit;
            font-size: 12px;
            width: 300px;
            outline: none;
            transition: border-color 0.15s;
        }
        .path-form input:focus { border-color: var(--green-mid); }
        .path-form button {
            padding: 7px 14px;
            background: var(--green-dim);
            border: 1px solid var(--green-mid);
            border-left: none;
            border-radius: 0 5px 5px 0;
            color: var(--green);
            font-family: inherit;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.15s;
        }
        .path-form button:hover { background: var(--green-mid); }

        /* Action buttons */
        .action-bar {
            padding: 10px 20px;
            background: var(--bg3);
            border-bottom: 1px solid var(--border2);
            display: flex;
            gap: 8px;
            align-items: center;
        }
        .btn {
            padding: 7px 14px;
            border-radius: 5px;
            font-family: inherit;
            font-size: 11px;
            letter-spacing: 0.5px;
            cursor: pointer;
            border: 1px solid transparent;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.15s;
            color: var(--text2);
            background: transparent;
        }
        .btn svg { opacity: 0.7; }
        .btn:hover svg { opacity: 1; }
        .btn-upload { border-color: #38bdf830; color: var(--blue); }
        .btn-upload:hover { background: #38bdf810; border-color: #38bdf850; box-shadow: 0 0 12px #38bdf815; }
        .btn-mkdir { border-color: var(--green-mid); color: var(--green); }
        .btn-mkdir:hover { background: var(--green-dim); box-shadow: 0 0 12px var(--green-dim); }
        .btn-mkfile { border-color: #a78bfa30; color: var(--purple); }
        .btn-mkfile:hover { background: #a78bfa10; border-color: #a78bfa50; }

        /* Message */
        .message {
            margin: 12px 20px 0;
            padding: 10px 14px;
            border-radius: 5px;
            font-size: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .message.success { background: #00ff6408; border: 1px solid var(--green-mid); color: var(--green); }
        .message.error { background: var(--red-dim); border: 1px solid #ff444440; color: var(--red); }

        /* File list */
        .file-list { flex: 1; overflow-y: auto; }
        .file-list::-webkit-scrollbar { width: 6px; }
        .file-list::-webkit-scrollbar-track { background: transparent; }
        .file-list::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
        
        table { width: 100%; border-collapse: collapse; }
        thead th {
            padding: 10px 16px;
            text-align: left;
            font-size: 10px;
            color: var(--text4);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            border-bottom: 1px solid var(--border);
            background: var(--bg3);
            position: sticky;
            top: 0;
            z-index: 5;
            font-weight: 400;
        }
        tbody tr { border-bottom: 1px solid var(--border2); transition: background 0.1s; }
        tbody tr:hover { background: #ffffff05; }
        td { padding: 9px 16px; vertical-align: middle; }
        
        .file-icon { color: var(--text3); display: flex; align-items: center; }
        .dir-icon { color: var(--yellow); }
        
        .file-name-cell { display: flex; align-items: center; gap: 10px; }
        .file-name-link { color: var(--text); text-decoration: none; transition: color 0.1s; }
        .file-name-link:hover { color: var(--blue); }
        .dir-link { color: var(--yellow) !important; }
        .dir-link:hover { color: #fde68a !important; }
        
        td.size { color: var(--text3); font-size: 12px; }
        td.modified { color: var(--text3); font-size: 12px; }
        td.perms { color: var(--text4); font-size: 11px; font-family: monospace; }
        
        .row-actions { display: flex; gap: 4px; opacity: 0; transition: opacity 0.1s; }
        tr:hover .row-actions { opacity: 1; }
        .row-btn {
            padding: 4px 8px;
            border-radius: 4px;
            font-family: inherit;
            font-size: 10px;
            cursor: pointer;
            border: 1px solid var(--border);
            background: transparent;
            color: var(--text3);
            transition: all 0.1s;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }
        .row-btn:hover { color: var(--text); border-color: var(--text3); }
        .row-btn-edit:hover { color: var(--blue); border-color: #38bdf840; background: #38bdf810; }
        .row-btn-dl:hover { color: var(--green); border-color: var(--green-mid); background: var(--green-dim); }
        .row-btn-ren:hover { color: var(--purple); border-color: #a78bfa40; background: #a78bfa10; }
        .row-btn-del:hover { color: var(--red); border-color: #ff444440; background: var(--red-dim); }

        .empty-state {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 80px 20px;
            color: var(--text4);
            gap: 12px;
        }
        .empty-state svg { opacity: 0.3; }

        /* Modals */
        .modal-backdrop {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.7);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }
        .modal-backdrop.active { display: flex; }
        .modal {
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 28px;
            width: 420px;
            max-width: 90vw;
        }
        .modal h3 {
            font-size: 14px;
            color: var(--text);
            margin-bottom: 20px;
            padding-bottom: 14px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .modal label { display: block; color: var(--text3); font-size: 10px; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }
        .modal input[type="text"],
        .modal input[type="file"] {
            width: 100%;
            padding: 10px 12px;
            background: var(--bg);
            border: 1px solid var(--border);
            border-radius: 5px;
            color: var(--text);
            font-family: inherit;
            font-size: 12px;
            outline: none;
            margin-bottom: 18px;
            transition: border-color 0.15s;
        }
        .modal input:focus { border-color: var(--green-mid); }
        .modal-actions { display: flex; gap: 8px; }
        .modal-btn {
            padding: 9px 20px;
            border-radius: 5px;
            font-family: inherit;
            font-size: 12px;
            cursor: pointer;
            border: 1px solid transparent;
            transition: all 0.15s;
        }
        .modal-btn-primary { background: var(--green-dim); border-color: var(--green-mid); color: var(--green); }
        .modal-btn-primary:hover { background: #00ff6425; box-shadow: 0 0 14px var(--green-dim); }
        .modal-btn-cancel { background: transparent; border-color: var(--border); color: var(--text3); }
        .modal-btn-cancel:hover { border-color: var(--text3); color: var(--text); }
        .modal-btn-danger { background: var(--red-dim); border-color: #ff444440; color: var(--red); }
        .modal-btn-danger:hover { background: #ff444430; }
        
        .confirm-msg { font-size: 12px; color: var(--text2); margin-bottom: 20px; line-height: 1.6; }
        .confirm-msg strong { color: var(--red); }

        /* Scrollbar for sidebar */
        .sidebar::-webkit-scrollbar { width: 4px; }
        .sidebar::-webkit-scrollbar-track { background: transparent; }
        .sidebar::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
    </style>
</head>
<body>

<!-- Topbar -->
<div class="topbar">
    <div class="topbar-brand">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
        FILE MANAGER
    </div>
    <div class="topbar-path">
        <span><?php echo htmlspecialchars($currentPath); ?></span>
    </div>
    <div class="topbar-right">
        <span><?php echo htmlspecialchars(get_current_user()); ?></span>
        <span class="sep">//</span>
        <span><?php echo $sessionDuration; ?></span>
        <span class="sep">//</span>
        <a href="?logout">logout</a>
    </div>
</div>

<div class="layout">
    <!-- Sidebar -->
    <aside class="sidebar">
        <div class="sidebar-section">
            <div class="sidebar-label">Quick Access</div>
            <form method="GET" style="display:contents;">
                <button type="submit" name="path" value="/" class="sidebar-item <?php echo $currentPath === '/' ? 'active' : ''; ?>">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
                    Root /
                </button>
            </form>
            <form method="GET" style="display:contents;">
                <button type="submit" name="path" value="/home" class="sidebar-item <?php echo $currentPath === '/home' ? 'active' : ''; ?>">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    /home
                </button>
            </form>
            <form method="GET" style="display:contents;">
                <button type="submit" name="path" value="<?php echo FM_ROOT_PATH; ?>" class="sidebar-item <?php echo $currentPath === realpath(FM_ROOT_PATH) ? 'active' : ''; ?>">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                    Script Dir
                </button>
            </form>
        </div>
        <?php if (!empty($userDirs)): ?>
        <div class="sidebar-section">
            <div class="sidebar-label">Users</div>
            <?php foreach ($userDirs as $userDir): ?>
            <form method="GET" style="display:contents;">
                <button type="submit" name="path" value="<?php echo htmlspecialchars($userDir); ?>" class="sidebar-item <?php echo $currentPath === realpath($userDir) ? 'active' : ''; ?>">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    <?php echo htmlspecialchars(basename($userDir)); ?>
                </button>
            </form>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </aside>

    <!-- Main -->
    <main class="main">
        <!-- Toolbar with breadcrumb & path nav -->
        <div class="toolbar">
            <div class="breadcrumb">
                <a href="?path=/">~</a>
                <?php foreach ($breadcrumb as $crumb): ?>
                    <span class="sep">/</span>
                    <a href="?path=<?php echo urlencode($crumb['path']); ?>"><?php echo htmlspecialchars($crumb['name']); ?></a>
                <?php endforeach; ?>
            </div>
            <form method="GET" class="path-form">
                <input type="text" name="path" placeholder="Navigate to path..." value="<?php echo htmlspecialchars($currentPath); ?>">
                <button type="submit">Go</button>
            </form>
        </div>

        <!-- Actions -->
        <div class="action-bar">
            <button onclick="showModal('uploadModal')" class="btn btn-upload">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
                Upload
            </button>
            <button onclick="showModal('createFolderModal')" class="btn btn-mkdir">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                New Folder
            </button>
            <button onclick="showModal('createFileModal')" class="btn btn-mkfile">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
                New File
            </button>
        </div>

        <?php if ($message): ?>
        <div class="message <?php echo $messageType; ?>">
            <?php echo $messageType === 'success' ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><polyline points="20 6 9 17 4 12"/></svg>' : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'; ?>
            <?php echo htmlspecialchars($message); ?>
        </div>
        <?php endif; ?>

        <!-- File List -->
        <div class="file-list">
            <?php if (empty($items)): ?>
                <div class="empty-state">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" width="48" height="48"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                    <span>Empty directory</span>
                </div>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Size</th>
                            <th>Modified</th>
                            <th>Mode</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($items as $item): ?>
                        <tr>
                            <td>
                                <div class="file-name-cell">
                                    <?php if ($item['is_dir']): ?>
                                        <span class="file-icon dir-icon"><?php echo getFileIcon(true, $item['name']); ?></span>
                                        <a href="?path=<?php echo urlencode($currentPath . '/' . $item['name']); ?>" class="file-name-link dir-link"><?php echo htmlspecialchars($item['name']); ?></a>
                                    <?php else: ?>
                                        <span class="file-icon"><?php echo getFileIcon(false, $item['name']); ?></span>
                                        <span class="file-name-link"><?php echo htmlspecialchars($item['name']); ?></span>
                                    <?php endif; ?>
                                </div>
                            </td>
                            <td class="size"><?php echo htmlspecialchars($item['size']); ?></td>
                            <td class="modified"><?php echo htmlspecialchars($item['modified']); ?></td>
                            <td class="perms"><?php echo htmlspecialchars($item['permissions']); ?></td>
                            <td>
                                <div class="row-actions">
                                    <?php if (!$item['is_dir'] && isEditableFile($item['name'])): ?>
                                        <a href="?path=<?php echo urlencode($currentPath); ?>&edit=<?php echo urlencode($item['name']); ?>" class="row-btn row-btn-edit">
                                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="11" height="11"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                                            edit
                                        </a>
                                    <?php endif; ?>
                                    <?php if (!$item['is_dir']): ?>
                                        <a href="?path=<?php echo urlencode($currentPath); ?>&download=<?php echo urlencode($item['name']); ?>" class="row-btn row-btn-dl">
                                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="11" height="11"><polyline points="8 17 12 21 16 17"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.88 18.09A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.29"/></svg>
                                            dl
                                        </a>
                                    <?php endif; ?>
                                    <?php if ($item['name'] !== '..' && $item['name'] !== '.'): ?>
                                        <button onclick="showRenameModal('<?php echo htmlspecialchars(addslashes($item['name'])); ?>')" class="row-btn row-btn-ren">
                                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="11" height="11"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
                                            ren
                                        </button>
                                        <button onclick="showDeleteModal('<?php echo htmlspecialchars(addslashes($item['name'])); ?>')" class="row-btn row-btn-del">
                                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="11" height="11"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
                                            rm
                                        </button>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </main>
</div>

<!-- Upload Modal -->
<div id="uploadModal" class="modal-backdrop">
    <div class="modal">
        <h3>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
            Upload File
        </h3>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?php echo SecurityHelper::generateCSRFToken(); ?>">
            <label>Select File (max <?php echo FM_MAX_UPLOAD_SIZE_MB; ?>MB)</label>
            <input type="file" name="upload_file" required>
            <div class="modal-actions">
                <button type="submit" class="modal-btn modal-btn-primary">Upload</button>
                <button type="button" onclick="hideModal('uploadModal')" class="modal-btn modal-btn-cancel">Cancel</button>
            </div>
        </form>
    </div>
</div>

<!-- Create Folder Modal -->
<div id="createFolderModal" class="modal-backdrop">
    <div class="modal">
        <h3>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
            New Folder
        </h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo SecurityHelper::generateCSRFToken(); ?>">
            <label>Folder Name</label>
            <input type="text" name="folder_name" placeholder="my-folder" required>
            <div class="modal-actions">
                <button type="submit" name="create_folder" class="modal-btn modal-btn-primary">Create</button>
                <button type="button" onclick="hideModal('createFolderModal')" class="modal-btn modal-btn-cancel">Cancel</button>
            </div>
        </form>
    </div>
</div>

<!-- Create File Modal -->
<div id="createFileModal" class="modal-backdrop">
    <div class="modal">
        <h3>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
            New File
        </h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo SecurityHelper::generateCSRFToken(); ?>">
            <label>File Name</label>
            <input type="text" name="file_name" placeholder="index.php" required>
            <div class="modal-actions">
                <button type="submit" name="create_file" class="modal-btn modal-btn-primary">Create</button>
                <button type="button" onclick="hideModal('createFileModal')" class="modal-btn modal-btn-cancel">Cancel</button>
            </div>
        </form>
    </div>
</div>

<!-- Rename Modal -->
<div id="renameModal" class="modal-backdrop">
    <div class="modal">
        <h3>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="15" height="15"><path d="M17 3a2.828 2.828 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5L17 3z"/></svg>
            Rename
        </h3>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo SecurityHelper::generateCSRFToken(); ?>">
            <input type="hidden" name="old_name" id="renameOldName">
            <label>New Name</label>
            <input type="text" name="new_name" id="renameNewName" placeholder="new-name" required>
            <div class="modal-actions">
                <button type="submit" name="rename_item" class="modal-btn modal-btn-primary">Rename</button>
                <button type="button" onclick="hideModal('renameModal')" class="modal-btn modal-btn-cancel">Cancel</button>
            </div>
        </form>
    </div>
</div>

<!-- Delete Modal -->
<div id="deleteModal" class="modal-backdrop">
    <div class="modal">
        <h3>
            <svg viewBox="0 0 24 24" fill="none" stroke="#ff6b6b" stroke-width="2" width="15" height="15"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>
            Confirm Delete
        </h3>
        <p class="confirm-msg">Are you sure you want to delete <strong id="deleteItemName"></strong>? This action cannot be undone.</p>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo SecurityHelper::generateCSRFToken(); ?>">
            <input type="hidden" name="item_name" id="deleteItemInput">
            <div class="modal-actions">
                <button type="submit" name="delete_item" class="modal-btn modal-btn-danger">Delete</button>
                <button type="button" onclick="hideModal('deleteModal')" class="modal-btn modal-btn-cancel">Cancel</button>
            </div>
        </form>
    </div>
</div>

<script>
function showModal(id) {
    document.getElementById(id).classList.add('active');
}
function hideModal(id) {
    document.getElementById(id).classList.remove('active');
}
function showRenameModal(name) {
    document.getElementById('renameOldName').value = name;
    document.getElementById('renameNewName').value = name;
    showModal('renameModal');
}
function showDeleteModal(name) {
    document.getElementById('deleteItemName').textContent = name;
    document.getElementById('deleteItemInput').value = name;
    showModal('deleteModal');
}
document.querySelectorAll('.modal-backdrop').forEach(el => {
    el.addEventListener('click', function(e) {
        if (e.target === this) this.classList.remove('active');
    });
});
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') document.querySelectorAll('.modal-backdrop.active').forEach(el => el.classList.remove('active'));
});
</script>
</body>
</html>
