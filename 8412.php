<?php
/**
 * PHP File Manager — Editorial Edition
 * Single-file implementation with authentication and security features
 * Version: 3.0
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
        if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        return $_SESSION['csrf_token'];
    }
    public static function validateCSRFToken($token) {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
    public static function sanitizePath($path) {
        $path = str_replace(['../', '..\\'], '', $path);
        return preg_replace('#/+#', '/', $path);
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
            self::logout(); return false;
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
    public static function logout() { session_unset(); session_destroy(); }
}

function formatSize($bytes) {
    $units = ['B','KB','MB','GB','TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, 2) . ' ' . $units[$pow];
}

function getFileType($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $map = [
        'php'=>'PHP','html'=>'HTML','htm'=>'HTML','css'=>'CSS','js'=>'JS',
        'json'=>'JSON','xml'=>'XML','txt'=>'TXT','md'=>'MD','log'=>'LOG',
        'sql'=>'SQL','csv'=>'CSV','ini'=>'INI','yml'=>'YML','yaml'=>'YML',
        'conf'=>'CNF','py'=>'PY','sh'=>'SH','bat'=>'BAT','cpp'=>'C++',
        'c'=>'C','h'=>'H','hpp'=>'H++',
    ];
    return $map[$ext] ?? strtoupper($ext) ?: '—';
}

function getFileColor($filename, $isDir) {
    if ($isDir) return '#C8A882';
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $colors = [
        'php'=>'#7C9E8C','html'=>'#C8714A','css'=>'#4A7EC8','js'=>'#C8A840',
        'json'=>'#8C7EC8','xml'=>'#C88C4A','txt'=>'#8C8C8C','md'=>'#4A9EC8',
        'sql'=>'#C84A7E','py'=>'#4AC87E','sh'=>'#C84A4A','log'=>'#9E9E6C',
        'csv'=>'#4AC8A0','yml'=>'#A04AC8','yaml'=>'#A04AC8',
    ];
    return $colors[$ext] ?? '#A09080';
}

function isEditableFile($filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return in_array($ext, explode(',', FM_ALLOWED_EXTENSIONS));
}

function getUserDirectories() {
    $dirs = [];
    if (is_dir('/home') && is_readable('/home')) {
        $scan = @scandir('/home');
        if ($scan) foreach ($scan as $item)
            if ($item !== '.' && $item !== '..' && is_dir('/home/' . $item))
                $dirs[] = '/home/' . $item;
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
            header('Location: ' . $_SERVER['PHP_SELF']); exit;
        } else { $loginError = 'Wrong password — try again.'; }
    }
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>File Manager</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,700;1,400&family=Lora:ital,wght@0,400;0,500;1,400&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: 'Lora', Georgia, serif;
    background: #F5EFE4;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
    overflow: hidden;
}

body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
        radial-gradient(ellipse 80% 60% at 20% 80%, #E8D5B7 0%, transparent 60%),
        radial-gradient(ellipse 60% 80% at 80% 20%, #D4C4A8 0%, transparent 60%);
    pointer-events: none;
}

/* Decorative circles */
.deco {
    position: fixed;
    border-radius: 50%;
    pointer-events: none;
}
.deco-1 {
    width: 500px; height: 500px;
    background: radial-gradient(circle, #C8A87020 0%, transparent 70%);
    top: -150px; right: -100px;
}
.deco-2 {
    width: 400px; height: 400px;
    background: radial-gradient(circle, #A0784020 0%, transparent 70%);
    bottom: -100px; left: -100px;
}

.card {
    position: relative;
    z-index: 10;
    width: 440px;
    background: #FDFAF4;
    border-radius: 24px;
    box-shadow:
        0 2px 0 #C8A882,
        0 8px 40px rgba(120, 90, 50, 0.15),
        inset 0 1px 0 rgba(255,255,255,0.8);
    overflow: hidden;
    animation: riseIn 0.6s cubic-bezier(0.34, 1.56, 0.64, 1) both;
}

@keyframes riseIn {
    from { opacity: 0; transform: translateY(30px) scale(0.96); }
    to { opacity: 1; transform: translateY(0) scale(1); }
}

.card-top {
    background: #2C1E0F;
    padding: 36px 40px 32px;
    position: relative;
    overflow: hidden;
}

.card-top::before {
    content: '';
    position: absolute;
    top: -40px; right: -40px;
    width: 160px; height: 160px;
    border-radius: 50%;
    background: rgba(200, 168, 130, 0.12);
}

.card-top::after {
    content: '';
    position: absolute;
    bottom: -20px; left: 60px;
    width: 80px; height: 80px;
    border-radius: 50%;
    background: rgba(200, 168, 130, 0.08);
}

.eyebrow {
    font-family: 'Lora', serif;
    font-size: 10px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: #C8A882;
    margin-bottom: 10px;
    position: relative;
    z-index: 1;
}

.card-top h1 {
    font-family: 'Playfair Display', Georgia, serif;
    font-size: 32px;
    font-weight: 700;
    color: #F5EFE4;
    line-height: 1.1;
    position: relative;
    z-index: 1;
}

.card-top h1 em {
    font-style: italic;
    color: #C8A882;
}

.card-body { padding: 36px 40px 40px; }

.error-msg {
    background: #FDF0EC;
    border: 1px solid #E8A898;
    border-radius: 10px;
    padding: 12px 16px;
    color: #A05040;
    font-size: 13px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.field-label {
    display: block;
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: #A09080;
    margin-bottom: 8px;
}

.field-input {
    width: 100%;
    padding: 14px 18px;
    background: #F5EFE4;
    border: 2px solid #E0D5C5;
    border-radius: 12px;
    font-family: 'Lora', serif;
    font-size: 15px;
    color: #2C1E0F;
    outline: none;
    transition: all 0.2s;
    margin-bottom: 24px;
    letter-spacing: 2px;
}

.field-input:focus {
    border-color: #C8A882;
    background: #FDFAF4;
    box-shadow: 0 0 0 4px rgba(200, 168, 130, 0.15);
}

.submit-btn {
    width: 100%;
    padding: 15px;
    background: #2C1E0F;
    color: #F5EFE4;
    border: none;
    border-radius: 12px;
    font-family: 'Playfair Display', serif;
    font-size: 16px;
    font-style: italic;
    cursor: pointer;
    transition: all 0.2s;
    position: relative;
    overflow: hidden;
}

.submit-btn::after {
    content: '';
    position: absolute;
    inset: 0;
    background: linear-gradient(135deg, rgba(200,168,130,0.15) 0%, transparent 100%);
    opacity: 0;
    transition: opacity 0.2s;
}

.submit-btn:hover { background: #3D2A14; transform: translateY(-1px); box-shadow: 0 4px 20px rgba(44,30,15,0.3); }
.submit-btn:hover::after { opacity: 1; }
.submit-btn:active { transform: translateY(0); }

.card-footer {
    padding: 16px 40px;
    border-top: 1px solid #EDE5D8;
    font-size: 11px;
    color: #B0A090;
    text-align: center;
    letter-spacing: 0.5px;
}
</style>
</head>
<body>
<div class="deco deco-1"></div>
<div class="deco deco-2"></div>
<div class="card">
    <div class="card-top">
        <div class="eyebrow">System Access</div>
        <h1>File <em>Manager</em></h1>
    </div>
    <div class="card-body">
        <?php if (isset($loginError)): ?>
        <div class="error-msg">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <?php echo htmlspecialchars($loginError); ?>
        </div>
        <?php endif; ?>
        <form method="POST">
            <label class="field-label">Password</label>
            <input class="field-input" type="password" name="password" placeholder="············" required autofocus>
            <button class="submit-btn" type="submit">Enter the vault →</button>
        </form>
    </div>
    <div class="card-footer">Protected access · Session expires in 60 min</div>
</div>
</body>
</html>
<?php exit; }

// ---- AUTHENTICATED SECTION ----

$currentPath = FM_ROOT_PATH;
$message = ''; $messageType = '';

if (isset($_GET['path'])) {
    $rp = SecurityHelper::sanitizePath($_GET['path']);
    $checkPath = ($rp[0] === '/') ? $rp : FM_ROOT_PATH . '/' . $rp;
    if (is_dir($checkPath) && SecurityHelper::isPathAllowed($checkPath))
        $currentPath = realpath($checkPath);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !SecurityHelper::validateCSRFToken($_POST['csrf_token'])) {
        $message = 'Security token mismatch.'; $messageType = 'error';
    } else {
        if (isset($_FILES['upload_file'])) {
            $uploadPath = $currentPath . '/' . basename($_FILES['upload_file']['name']);
            $maxSize = FM_MAX_UPLOAD_SIZE_MB * 1024 * 1024;
            if ($_FILES['upload_file']['size'] > $maxSize) { $message = 'File too large.'; $messageType = 'error'; }
            elseif (move_uploaded_file($_FILES['upload_file']['tmp_name'], $uploadPath)) { $message = 'File uploaded.'; $messageType = 'success'; }
            else { $message = 'Upload failed.'; $messageType = 'error'; }
        }
        if (isset($_POST['create_folder'])) {
            $fn = basename($_POST['folder_name']);
            $message = mkdir($currentPath . '/' . $fn, 0755) ? 'Folder created.' : 'Could not create folder.';
            $messageType = mkdir($currentPath . '/' . $fn, 0755) !== false ? 'success' : 'error';
            // correct logic
            $nf = $currentPath . '/' . $fn;
            if (!is_dir($nf)) { if(mkdir($nf, 0755)){ $message = 'Folder created.'; $messageType='success'; } else { $message='Could not create folder.'; $messageType='error'; } }
            else { $message='Folder already exists.'; $messageType='error'; }
        }
        if (isset($_POST['create_file'])) {
            $fn = basename($_POST['file_name']);
            $nf = $currentPath . '/' . $fn;
            if (file_put_contents($nf, '') !== false) { $message = 'File created.'; $messageType = 'success'; }
            else { $message = 'Could not create file.'; $messageType = 'error'; }
        }
        if (isset($_POST['rename_item'])) {
            $old = $currentPath . '/' . basename($_POST['old_name']);
            $new = $currentPath . '/' . basename($_POST['new_name']);
            if (rename($old, $new)) { $message = 'Renamed.'; $messageType = 'success'; }
            else { $message = 'Rename failed.'; $messageType = 'error'; }
        }
        if (isset($_POST['delete_item'])) {
            $ip = $currentPath . '/' . basename($_POST['item_name']);
            function deleteDirectory($dir) {
                if (!is_dir($dir)) return unlink($dir);
                foreach (array_diff(scandir($dir), ['.','..']) as $item) {
                    $p = $dir . '/' . $item;
                    is_dir($p) ? deleteDirectory($p) : unlink($p);
                }
                return rmdir($dir);
            }
            if (deleteDirectory($ip)) { $message = 'Deleted.'; $messageType = 'success'; }
            else { $message = 'Delete failed.'; $messageType = 'error'; }
        }
        if (isset($_POST['save_file'])) {
            $fp = SecurityHelper::sanitizePath($_POST['file_path']);
            if (file_put_contents($fp, $_POST['file_content']) !== false) { $message = 'Saved.'; $messageType = 'success'; }
            else { $message = 'Save failed.'; $messageType = 'error'; }
        }
    }
}

if (isset($_GET['download'])) {
    $df = $currentPath . '/' . basename($_GET['download']);
    if (file_exists($df) && is_file($df)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($df) . '"');
        header('Content-Length: ' . filesize($df));
        readfile($df); exit;
    }
}

if (isset($_GET['edit'])) {
    $ef = $currentPath . '/' . basename($_GET['edit']);
    if (file_exists($ef) && is_file($ef) && isEditableFile($ef)) {
        $fc = file_get_contents($ef);
        $fsize = formatSize(filesize($ef));
        $fmod = date('d M Y, H:i', filemtime($ef));
        $fext = strtoupper(pathinfo($ef, PATHINFO_EXTENSION));
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Edit · <?php echo htmlspecialchars(basename($ef)); ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,700;1,400&family=Lora:wght@400;500&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
:root {
    --cream: #F5EFE4;
    --cream2: #FDFAF4;
    --brown: #2C1E0F;
    --gold: #C8A882;
    --border: #E0D5C5;
    --muted: #A09080;
}
body { font-family: 'Lora', serif; background: var(--cream); height: 100vh; display: flex; flex-direction: column; overflow: hidden; }

.editor-top {
    background: var(--brown);
    padding: 14px 28px;
    display: flex;
    align-items: center;
    gap: 20px;
    flex-shrink: 0;
}
.editor-top .back-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    color: var(--gold);
    text-decoration: none;
    font-size: 12px;
    letter-spacing: 1px;
    text-transform: uppercase;
    opacity: 0.8;
    transition: opacity 0.15s;
    padding: 6px 12px;
    border: 1px solid rgba(200,168,130,0.25);
    border-radius: 8px;
}
.editor-top .back-btn:hover { opacity: 1; }

.editor-top .file-info { flex: 1; }
.editor-top .file-name {
    font-family: 'Playfair Display', serif;
    font-size: 18px;
    font-style: italic;
    color: var(--cream);
}
.editor-top .file-meta { font-size: 11px; color: var(--gold); opacity: 0.7; margin-top: 2px; letter-spacing: 0.5px; }

.editor-top .save-btn {
    padding: 10px 24px;
    background: var(--gold);
    color: var(--brown);
    border: none;
    border-radius: 10px;
    font-family: 'Playfair Display', serif;
    font-size: 14px;
    font-style: italic;
    cursor: pointer;
    transition: all 0.15s;
    flex-shrink: 0;
}
.editor-top .save-btn:hover { background: #D4B890; transform: translateY(-1px); box-shadow: 0 4px 16px rgba(200,168,130,0.4); }

.editor-body {
    flex: 1;
    display: flex;
    overflow: hidden;
    background: var(--cream2);
}
.line-gutter {
    background: #F0E8D8;
    border-right: 1px solid var(--border);
    padding: 16px 12px;
    font-family: 'Fira Code', monospace;
    font-size: 12px;
    color: #C0B0A0;
    text-align: right;
    min-width: 52px;
    overflow: hidden;
    white-space: pre;
    line-height: 1.7;
    user-select: none;
}
textarea {
    flex: 1;
    padding: 16px 20px;
    background: transparent;
    border: none;
    font-family: 'Fira Code', monospace;
    font-size: 13px;
    line-height: 1.7;
    color: var(--brown);
    resize: none;
    outline: none;
    tab-size: 4;
    caret-color: var(--gold);
}
textarea::selection { background: rgba(200,168,130,0.3); }

.editor-foot {
    background: var(--brown);
    padding: 7px 24px;
    display: flex;
    gap: 24px;
    align-items: center;
    flex-shrink: 0;
}
.status-pill {
    font-size: 10px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    color: rgba(200,168,130,0.6);
    display: flex;
    align-items: center;
    gap: 6px;
}
.status-pill span { color: var(--gold); }
</style>
</head>
<body>
<form method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($ef))); ?>" style="display:flex;flex-direction:column;height:100vh;overflow:hidden;">
<input type="hidden" name="csrf_token" value="<?php echo SecurityHelper::generateCSRFToken(); ?>">
<input type="hidden" name="file_path" value="<?php echo htmlspecialchars($ef); ?>">

<div class="editor-top">
    <a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($ef))); ?>" class="back-btn">
        ← Back
    </a>
    <div class="file-info">
        <div class="file-name"><?php echo htmlspecialchars(basename($ef)); ?></div>
        <div class="file-meta"><?php echo $fext; ?> · <?php echo $fsize; ?> · <?php echo $fmod; ?></div>
    </div>
    <button type="submit" name="save_file" class="save-btn">Save changes →</button>
</div>

<div class="editor-body">
    <div class="line-gutter" id="gutter">1</div>
    <textarea name="file_content" id="ed" spellcheck="false" oninput="upd()" onscroll="sync()"><?php echo htmlspecialchars($fc); ?></textarea>
</div>

<div class="editor-foot">
    <div class="status-pill">Lines <span id="lcount">1</span></div>
    <div class="status-pill">Cursor <span id="cpos">1:1</span></div>
    <div class="status-pill">Encoding <span>UTF-8</span></div>
</div>
</form>
<script>
const ed = document.getElementById('ed'), g = document.getElementById('gutter');
function upd() {
    const n = ed.value.split('\n').length;
    g.textContent = Array.from({length:n},(_,i)=>i+1).join('\n');
    document.getElementById('lcount').textContent = n;
}
function sync() { g.scrollTop = ed.scrollTop; }
ed.addEventListener('keyup', () => {
    const lines = ed.value.substring(0, ed.selectionStart).split('\n');
    document.getElementById('cpos').textContent = `${lines.length}:${lines[lines.length-1].length+1}`;
});
ed.addEventListener('keydown', e => {
    if (e.key === 'Tab') { e.preventDefault(); const s=ed.selectionStart; ed.value=ed.value.substring(0,s)+'    '+ed.value.substring(ed.selectionEnd); ed.selectionStart=ed.selectionEnd=s+4; upd(); }
});
upd();
</script>
</body>
</html>
<?php exit; } }

// ---- MAIN FILE BROWSER ----

$items = [];
if (is_readable($currentPath)) {
    foreach (scandir($currentPath) as $item) {
        if ($item === '.' || (!FM_SHOW_HIDDEN && $item[0] === '.' && $item !== '..')) continue;
        $ip = $currentPath . '/' . $item;
        $isDir = is_dir($ip);
        $items[] = [
            'name' => $item,
            'is_dir' => $isDir,
            'size' => $isDir ? '—' : formatSize(filesize($ip)),
            'modified' => date('d M Y', filemtime($ip)),
            'time' => date('H:i', filemtime($ip)),
            'permissions' => substr(sprintf('%o', fileperms($ip)), -4),
            'color' => getFileColor($item, $isDir),
            'type' => $isDir ? 'DIR' : getFileType($item),
        ];
    }
    usort($items, fn($a, $b) => $b['is_dir'] <=> $a['is_dir'] ?: strcmp($a['name'], $b['name']));
}

$pathParts = explode('/', str_replace('\\', '/', $currentPath));
$breadcrumb = []; $cp = '';
foreach ($pathParts as $p) {
    if ($p === '') continue;
    $cp .= '/' . $p;
    $breadcrumb[] = ['name' => $p, 'path' => $cp];
}

$userDirs = getUserDirectories();
$sessionAge = gmdate('H:i:s', time() - $_SESSION['login_time']);
$csrf = SecurityHelper::generateCSRFToken();
$totalItems = count($items);
$totalFiles = count(array_filter($items, fn($i) => !$i['is_dir']));
$totalDirs = count(array_filter($items, fn($i) => $i['is_dir']));
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>File Manager · <?php echo htmlspecialchars(basename($currentPath) ?: '/'); ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,700;1,400;1,700&family=Lora:ital,wght@0,400;0,500;1,400&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
:root {
    --cream: #F5EFE4;
    --cream2: #FDFAF4;
    --cream3: #EDE5D5;
    --paper: #FAF6EE;
    --brown: #2C1E0F;
    --brown2: #3D2A14;
    --brown3: #4E3520;
    --gold: #C8A882;
    --gold2: #A07848;
    --border: #E0D5C5;
    --border2: #D0C5B0;
    --muted: #A09080;
    --muted2: #8A7A6A;
    --text: #3A2818;
    --green: #5A8A6A;
    --red: #A05040;
    --shadow: rgba(44,30,15,0.08);
    --shadow2: rgba(44,30,15,0.15);
}

html, body { height: 100%; }
body {
    font-family: 'Lora', Georgia, serif;
    background: var(--cream);
    color: var(--text);
    overflow: hidden;
}

/* ─── LAYOUT ─── */
.app { display: flex; height: 100vh; }

/* ─── SIDEBAR ─── */
.sidebar {
    width: 260px;
    min-width: 260px;
    background: var(--brown);
    display: flex;
    flex-direction: column;
    overflow: hidden;
    position: relative;
}

.sidebar::after {
    content: '';
    position: absolute;
    bottom: 0; right: 0;
    width: 120px; height: 120px;
    border-radius: 50%;
    background: rgba(200,168,130,0.06);
    pointer-events: none;
}

.sidebar-brand {
    padding: 28px 24px 24px;
    border-bottom: 1px solid rgba(200,168,130,0.12);
    position: relative;
}

.sidebar-brand .eyebrow {
    font-size: 9px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: rgba(200,168,130,0.5);
    margin-bottom: 6px;
}

.sidebar-brand h2 {
    font-family: 'Playfair Display', serif;
    font-size: 22px;
    font-weight: 700;
    color: var(--cream);
    line-height: 1;
}

.sidebar-brand h2 em {
    font-style: italic;
    color: var(--gold);
}

.sidebar-meta {
    font-size: 10px;
    color: rgba(200,168,130,0.4);
    margin-top: 8px;
    letter-spacing: 0.5px;
}

.sidebar-nav { flex: 1; overflow-y: auto; padding: 16px 0; }
.sidebar-nav::-webkit-scrollbar { width: 3px; }
.sidebar-nav::-webkit-scrollbar-thumb { background: rgba(200,168,130,0.2); border-radius: 2px; }

.nav-section { margin-bottom: 8px; }
.nav-section-label {
    padding: 8px 24px 4px;
    font-size: 9px;
    letter-spacing: 2.5px;
    text-transform: uppercase;
    color: rgba(200,168,130,0.35);
}

.nav-item {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 9px 24px;
    color: rgba(245,239,228,0.6);
    text-decoration: none;
    font-size: 13px;
    transition: all 0.15s;
    border-left: 2px solid transparent;
    background: none;
    border-top: none;
    border-right: none;
    border-bottom: none;
    width: 100%;
    font-family: 'Lora', serif;
    cursor: pointer;
    text-align: left;
}
.nav-item:hover { color: var(--cream); background: rgba(200,168,130,0.08); border-left-color: rgba(200,168,130,0.3); }
.nav-item.active { color: var(--gold); background: rgba(200,168,130,0.12); border-left-color: var(--gold); }

.nav-icon { width: 16px; flex-shrink: 0; opacity: 0.7; }
.nav-item:hover .nav-icon, .nav-item.active .nav-icon { opacity: 1; }

.sidebar-footer {
    padding: 16px 24px;
    border-top: 1px solid rgba(200,168,130,0.12);
}
.logout-btn {
    display: flex;
    align-items: center;
    gap: 8px;
    color: rgba(200,168,130,0.4);
    text-decoration: none;
    font-size: 12px;
    letter-spacing: 0.5px;
    transition: color 0.15s;
    background: none;
    border: none;
    cursor: pointer;
    font-family: 'Lora', serif;
    padding: 0;
}
.logout-btn:hover { color: #D4907A; }

/* ─── MAIN ─── */
.main { flex: 1; display: flex; flex-direction: column; overflow: hidden; min-width: 0; }

/* ─── TOPBAR ─── */
.topbar {
    background: var(--paper);
    border-bottom: 1px solid var(--border);
    padding: 0 28px;
    height: 56px;
    display: flex;
    align-items: center;
    gap: 12px;
    flex-shrink: 0;
}

.breadcrumb {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 0;
    overflow: hidden;
    min-width: 0;
}
.breadcrumb a, .breadcrumb span.crumb-text {
    color: var(--muted);
    text-decoration: none;
    font-size: 13px;
    padding: 4px 8px;
    border-radius: 6px;
    transition: all 0.15s;
    white-space: nowrap;
}
.breadcrumb a:hover { color: var(--text); background: var(--cream3); }
.breadcrumb .sep { color: var(--border2); font-size: 16px; padding: 0 2px; }
.breadcrumb a:last-child { color: var(--text); font-weight: 500; }

.path-go {
    display: flex;
    gap: 0;
}
.path-go input {
    padding: 8px 14px;
    background: var(--cream);
    border: 1px solid var(--border);
    border-radius: 8px 0 0 8px;
    font-family: 'DM Mono', monospace;
    font-size: 12px;
    color: var(--text);
    outline: none;
    width: 240px;
    transition: border-color 0.15s;
}
.path-go input:focus { border-color: var(--gold); }
.path-go button {
    padding: 8px 16px;
    background: var(--gold);
    border: 1px solid var(--gold);
    border-left: none;
    border-radius: 0 8px 8px 0;
    color: var(--brown);
    font-family: 'Lora', serif;
    font-size: 12px;
    cursor: pointer;
    transition: background 0.15s;
    font-weight: 500;
}
.path-go button:hover { background: var(--gold2); border-color: var(--gold2); color: white; }

/* ─── ACTION STRIP ─── */
.action-strip {
    background: var(--cream2);
    border-bottom: 1px solid var(--border);
    padding: 10px 28px;
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
}

.act-btn {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 8px 16px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--paper);
    color: var(--text);
    font-family: 'Lora', serif;
    font-size: 12px;
    cursor: pointer;
    transition: all 0.15s;
    text-decoration: none;
    box-shadow: 0 1px 3px var(--shadow);
}
.act-btn:hover { border-color: var(--gold); background: var(--cream); box-shadow: 0 2px 8px var(--shadow2); transform: translateY(-1px); }
.act-btn svg { opacity: 0.6; transition: opacity 0.15s; }
.act-btn:hover svg { opacity: 1; }

.act-btn-primary { background: var(--brown); color: var(--cream); border-color: var(--brown3); }
.act-btn-primary:hover { background: var(--brown2); color: var(--cream); }
.act-btn-primary svg { opacity: 0.7; stroke: var(--cream); }

.stats-pill {
    margin-left: auto;
    font-size: 11px;
    color: var(--muted);
    background: var(--cream3);
    padding: 5px 12px;
    border-radius: 20px;
    border: 1px solid var(--border);
    display: flex;
    gap: 10px;
    align-items: center;
}
.stats-pill strong { color: var(--text); font-weight: 500; }

/* ─── ALERT ─── */
.alert {
    margin: 14px 28px 0;
    padding: 11px 16px;
    border-radius: 10px;
    font-size: 13px;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
}
.alert.success { background: #EDF5F0; border: 1px solid #A8D4B8; color: var(--green); }
.alert.error { background: #F5EDEC; border: 1px solid #D4A8A0; color: var(--red); }

/* ─── FILE TABLE ─── */
.file-area { flex: 1; overflow-y: auto; padding: 14px 28px 28px; }
.file-area::-webkit-scrollbar { width: 6px; }
.file-area::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 3px; }

.file-grid { background: var(--paper); border-radius: 14px; border: 1px solid var(--border); overflow: hidden; box-shadow: 0 2px 12px var(--shadow); }

table { width: 100%; border-collapse: collapse; }

thead th {
    padding: 12px 20px;
    text-align: left;
    font-size: 9px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--muted);
    background: var(--cream2);
    border-bottom: 1px solid var(--border);
    font-weight: 500;
    font-family: 'Lora', serif;
}

tbody tr {
    border-bottom: 1px solid var(--border);
    transition: background 0.1s;
}
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: var(--cream); }

td { padding: 11px 20px; vertical-align: middle; }

.type-badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 5px;
    font-family: 'DM Mono', monospace;
    font-size: 10px;
    font-weight: 500;
    letter-spacing: 0.5px;
    color: white;
    min-width: 36px;
    text-align: center;
}

.name-cell { display: flex; align-items: center; gap: 12px; }
.name-cell a { color: var(--text); text-decoration: none; font-size: 14px; transition: color 0.15s; }
.name-cell a:hover { color: var(--gold2); }
.dir-name { color: var(--gold2) !important; font-style: italic; }
td.size-col { font-family: 'DM Mono', monospace; font-size: 12px; color: var(--muted); }
td.date-col { font-size: 12px; color: var(--muted); }
td.date-col .time { font-size: 10px; color: var(--muted2); margin-top: 1px; }
td.perm-col { font-family: 'DM Mono', monospace; font-size: 11px; color: var(--border2); }

.row-actions { display: flex; gap: 4px; opacity: 0; transition: opacity 0.1s; }
tr:hover .row-actions { opacity: 1; }

.ract {
    padding: 5px 10px;
    border-radius: 6px;
    font-family: 'Lora', serif;
    font-size: 11px;
    cursor: pointer;
    border: 1px solid var(--border);
    background: var(--paper);
    color: var(--muted);
    transition: all 0.12s;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 4px;
}
.ract:hover { transform: translateY(-1px); box-shadow: 0 2px 6px var(--shadow2); }
.ract-edit:hover { color: #4A7EC8; border-color: #A0B8D8; background: #EEF3FA; }
.ract-dl:hover { color: var(--green); border-color: #A8D4B8; background: #EDF5F0; }
.ract-ren:hover { color: #8A6AC8; border-color: #C0A8D8; background: #F5EDF5; }
.ract-del:hover { color: var(--red); border-color: #D4A8A0; background: #F5EDEC; }

.empty-state {
    text-align: center;
    padding: 80px 20px;
    color: var(--muted);
}
.empty-state .empty-icon {
    font-size: 48px;
    margin-bottom: 16px;
    opacity: 0.4;
}
.empty-state p { font-style: italic; font-size: 15px; }

/* ─── MODALS ─── */
.backdrop {
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(44,30,15,0.45);
    z-index: 1000;
    align-items: center;
    justify-content: center;
    backdrop-filter: blur(3px);
}
.backdrop.open { display: flex; }

.modal {
    background: var(--paper);
    border-radius: 20px;
    width: 420px;
    max-width: 90vw;
    box-shadow: 0 20px 60px rgba(44,30,15,0.25);
    overflow: hidden;
    animation: modalIn 0.25s cubic-bezier(0.34, 1.56, 0.64, 1) both;
}
@keyframes modalIn {
    from { opacity: 0; transform: scale(0.9) translateY(20px); }
    to { opacity: 1; transform: scale(1) translateY(0); }
}

.modal-head {
    background: var(--brown);
    padding: 22px 28px;
}
.modal-head h3 {
    font-family: 'Playfair Display', serif;
    font-size: 20px;
    font-style: italic;
    color: var(--cream);
}
.modal-head p { font-size: 11px; color: var(--gold); opacity: 0.6; margin-top: 3px; letter-spacing: 0.5px; }

.modal-body { padding: 24px 28px; }

.form-field { margin-bottom: 18px; }
.form-label { display: block; font-size: 10px; letter-spacing: 2px; text-transform: uppercase; color: var(--muted); margin-bottom: 7px; }
.form-input {
    width: 100%;
    padding: 11px 14px;
    background: var(--cream);
    border: 1.5px solid var(--border);
    border-radius: 10px;
    font-family: 'Lora', serif;
    font-size: 14px;
    color: var(--text);
    outline: none;
    transition: border-color 0.15s;
}
.form-input:focus { border-color: var(--gold); box-shadow: 0 0 0 3px rgba(200,168,130,0.15); }

.modal-actions { display: flex; gap: 8px; padding: 0 28px 24px; }
.modal-btn {
    padding: 10px 22px;
    border-radius: 10px;
    font-family: 'Playfair Display', serif;
    font-size: 14px;
    font-style: italic;
    cursor: pointer;
    border: 1.5px solid transparent;
    transition: all 0.15s;
}
.modal-btn-primary { background: var(--brown); color: var(--cream); border-color: var(--brown3); }
.modal-btn-primary:hover { background: var(--brown2); transform: translateY(-1px); box-shadow: 0 4px 14px var(--shadow2); }
.modal-btn-danger { background: #F5EDEC; color: var(--red); border-color: #D4A8A0; }
.modal-btn-danger:hover { background: #EDD8D5; }
.modal-btn-cancel { background: transparent; color: var(--muted); border-color: var(--border); }
.modal-btn-cancel:hover { border-color: var(--border2); color: var(--text); }

.del-warning {
    background: #FDF5F0;
    border: 1px solid #E8C8B8;
    border-radius: 10px;
    padding: 14px 16px;
    font-size: 13px;
    color: var(--text);
    line-height: 1.6;
    margin-bottom: 20px;
}
.del-warning strong { color: var(--red); font-style: italic; }
</style>
</head>
<body>
<div class="app">

<!-- SIDEBAR -->
<aside class="sidebar">
    <div class="sidebar-brand">
        <div class="eyebrow">Workspace</div>
        <h2>File <em>Mgr.</em></h2>
        <div class="sidebar-meta"><?php echo htmlspecialchars(get_current_user()); ?> · <?php echo $sessionAge; ?></div>
    </div>
    <nav class="sidebar-nav">
        <div class="nav-section">
            <div class="nav-section-label">Locations</div>
            <form method="GET" style="display:contents;">
                <button type="submit" name="path" value="/" class="nav-item <?php echo $currentPath==='/'?'active':''; ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>
                    Root
                </button>
            </form>
            <form method="GET" style="display:contents;">
                <button type="submit" name="path" value="/home" class="nav-item <?php echo $currentPath==='/home'?'active':''; ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    Home
                </button>
            </form>
            <form method="GET" style="display:contents;">
                <button type="submit" name="path" value="<?php echo FM_ROOT_PATH; ?>" class="nav-item <?php echo $currentPath===realpath(FM_ROOT_PATH)?'active':''; ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
                    Script Dir
                </button>
            </form>
        </div>
        <?php if (!empty($userDirs)): ?>
        <div class="nav-section">
            <div class="nav-section-label">Users</div>
            <?php foreach ($userDirs as $ud): ?>
            <form method="GET" style="display:contents;">
                <button type="submit" name="path" value="<?php echo htmlspecialchars($ud); ?>" class="nav-item <?php echo $currentPath===realpath($ud)?'active':''; ?>">
                    <svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
                    <?php echo htmlspecialchars(basename($ud)); ?>
                </button>
            </form>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>
    </nav>
    <div class="sidebar-footer">
        <a href="?logout" class="logout-btn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            Sign out
        </a>
    </div>
</aside>

<!-- MAIN AREA -->
<div class="main">
    <!-- TOPBAR -->
    <div class="topbar">
        <nav class="breadcrumb">
            <a href="?path=/">~</a>
            <?php foreach ($breadcrumb as $crumb): ?>
                <span class="sep">/</span>
                <a href="?path=<?php echo urlencode($crumb['path']); ?>"><?php echo htmlspecialchars($crumb['name']); ?></a>
            <?php endforeach; ?>
        </nav>
        <form method="GET" class="path-go">
            <input type="text" name="path" placeholder="/path/to/navigate" value="<?php echo htmlspecialchars($currentPath); ?>">
            <button type="submit">Go</button>
        </form>
    </div>

    <!-- ACTION STRIP -->
    <div class="action-strip">
        <button onclick="openModal('upModal')" class="act-btn act-btn-primary">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/></svg>
            Upload
        </button>
        <button onclick="openModal('mkdirModal')" class="act-btn">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
            New Folder
        </button>
        <button onclick="openModal('mkfileModal')" class="act-btn">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="12" y1="18" x2="12" y2="12"/><line x1="9" y1="15" x2="15" y2="15"/></svg>
            New File
        </button>
        <div class="stats-pill">
            <span><strong><?php echo $totalDirs; ?></strong> folders</span>
            <span style="color:var(--border2)">·</span>
            <span><strong><?php echo $totalFiles; ?></strong> files</span>
        </div>
    </div>

    <?php if ($message): ?>
    <div class="alert <?php echo $messageType; ?>">
        <?php if ($messageType === 'success'): ?>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
        <?php else: ?>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
        <?php endif; ?>
        <?php echo htmlspecialchars($message); ?>
    </div>
    <?php endif; ?>

    <!-- FILE LIST -->
    <div class="file-area">
        <div class="file-grid">
            <?php if (empty($items)): ?>
            <div class="empty-state">
                <div class="empty-icon">🗂</div>
                <p>This directory is empty</p>
            </div>
            <?php else: ?>
            <table>
                <thead>
                    <tr>
                        <th style="width:40px">Type</th>
                        <th>Name</th>
                        <th style="width:90px">Size</th>
                        <th style="width:120px">Modified</th>
                        <th style="width:70px">Mode</th>
                        <th style="width:180px">Actions</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($items as $item): ?>
                <tr>
                    <td>
                        <span class="type-badge" style="background:<?php echo $item['color']; ?>">
                            <?php echo htmlspecialchars($item['type']); ?>
                        </span>
                    </td>
                    <td>
                        <div class="name-cell">
                            <?php if ($item['is_dir']): ?>
                                <a href="?path=<?php echo urlencode($currentPath . '/' . $item['name']); ?>" class="dir-name">
                                    <?php echo htmlspecialchars($item['name']); ?>
                                </a>
                            <?php else: ?>
                                <span><?php echo htmlspecialchars($item['name']); ?></span>
                            <?php endif; ?>
                        </div>
                    </td>
                    <td class="size-col"><?php echo htmlspecialchars($item['size']); ?></td>
                    <td class="date-col">
                        <?php echo htmlspecialchars($item['modified']); ?>
                        <div class="time"><?php echo htmlspecialchars($item['time']); ?></div>
                    </td>
                    <td class="perm-col"><?php echo htmlspecialchars($item['permissions']); ?></td>
                    <td>
                        <div class="row-actions">
                            <?php if (!$item['is_dir'] && isEditableFile($item['name'])): ?>
                            <a href="?path=<?php echo urlencode($currentPath); ?>&edit=<?php echo urlencode($item['name']); ?>" class="ract ract-edit">
                                Edit
                            </a>
                            <?php endif; ?>
                            <?php if (!$item['is_dir']): ?>
                            <a href="?path=<?php echo urlencode($currentPath); ?>&download=<?php echo urlencode($item['name']); ?>" class="ract ract-dl">
                                Save
                            </a>
                            <?php endif; ?>
                            <?php if ($item['name'] !== '..' && $item['name'] !== '.'): ?>
                            <button onclick="openRename('<?php echo htmlspecialchars(addslashes($item['name'])); ?>')" class="ract ract-ren">
                                Rename
                            </button>
                            <button onclick="openDelete('<?php echo htmlspecialchars(addslashes($item['name'])); ?>')" class="ract ract-del">
                                Delete
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
    </div>
</div>
</div>

<!-- Upload Modal -->
<div id="upModal" class="backdrop">
    <div class="modal">
        <div class="modal-head">
            <h3>Upload a file</h3>
            <p>Destination: <?php echo htmlspecialchars($currentPath); ?></p>
        </div>
        <form method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf; ?>">
            <div class="modal-body">
                <div class="form-field">
                    <label class="form-label">Choose file (max <?php echo FM_MAX_UPLOAD_SIZE_MB; ?>MB)</label>
                    <input type="file" name="upload_file" required class="form-input" style="padding:8px 14px;">
                </div>
            </div>
            <div class="modal-actions">
                <button type="submit" class="modal-btn modal-btn-primary">Upload →</button>
                <button type="button" onclick="closeModal('upModal')" class="modal-btn modal-btn-cancel">Cancel</button>
            </div>
        </form>
    </div>
</div>

<!-- New Folder Modal -->
<div id="mkdirModal" class="backdrop">
    <div class="modal">
        <div class="modal-head">
            <h3>New folder</h3>
            <p>Inside: <?php echo htmlspecialchars($currentPath); ?></p>
        </div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf; ?>">
            <div class="modal-body">
                <div class="form-field">
                    <label class="form-label">Folder name</label>
                    <input type="text" name="folder_name" placeholder="my-folder" required class="form-input" autofocus>
                </div>
            </div>
            <div class="modal-actions">
                <button type="submit" name="create_folder" class="modal-btn modal-btn-primary">Create →</button>
                <button type="button" onclick="closeModal('mkdirModal')" class="modal-btn modal-btn-cancel">Cancel</button>
            </div>
        </form>
    </div>
</div>

<!-- New File Modal -->
<div id="mkfileModal" class="backdrop">
    <div class="modal">
        <div class="modal-head">
            <h3>New file</h3>
            <p>Inside: <?php echo htmlspecialchars($currentPath); ?></p>
        </div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf; ?>">
            <div class="modal-body">
                <div class="form-field">
                    <label class="form-label">File name</label>
                    <input type="text" name="file_name" placeholder="index.php" required class="form-input">
                </div>
            </div>
            <div class="modal-actions">
                <button type="submit" name="create_file" class="modal-btn modal-btn-primary">Create →</button>
                <button type="button" onclick="closeModal('mkfileModal')" class="modal-btn modal-btn-cancel">Cancel</button>
            </div>
        </form>
    </div>
</div>

<!-- Rename Modal -->
<div id="renModal" class="backdrop">
    <div class="modal">
        <div class="modal-head">
            <h3>Rename item</h3>
            <p>Choose a new name below</p>
        </div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf; ?>">
            <input type="hidden" name="old_name" id="renOld">
            <div class="modal-body">
                <div class="form-field">
                    <label class="form-label">New name</label>
                    <input type="text" name="new_name" id="renNew" required class="form-input">
                </div>
            </div>
            <div class="modal-actions">
                <button type="submit" name="rename_item" class="modal-btn modal-btn-primary">Rename →</button>
                <button type="button" onclick="closeModal('renModal')" class="modal-btn modal-btn-cancel">Cancel</button>
            </div>
        </form>
    </div>
</div>

<!-- Delete Modal -->
<div id="delModal" class="backdrop">
    <div class="modal">
        <div class="modal-head">
            <h3>Delete item</h3>
            <p>This action is permanent</p>
        </div>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf; ?>">
            <input type="hidden" name="item_name" id="delItem">
            <div class="modal-body">
                <div class="del-warning">
                    Permanently delete <strong id="delName"></strong>? This cannot be undone.
                </div>
            </div>
            <div class="modal-actions">
                <button type="submit" name="delete_item" class="modal-btn modal-btn-danger">Delete</button>
                <button type="button" onclick="closeModal('delModal')" class="modal-btn modal-btn-cancel">Cancel</button>
            </div>
        </form>
    </div>
</div>

<script>
function openModal(id) { document.getElementById(id).classList.add('open'); }
function closeModal(id) { document.getElementById(id).classList.remove('open'); }

function openRename(name) {
    document.getElementById('renOld').value = name;
    document.getElementById('renNew').value = name;
    openModal('renModal');
    setTimeout(() => document.getElementById('renNew').select(), 50);
}

function openDelete(name) {
    document.getElementById('delItem').value = name;
    document.getElementById('delName').textContent = name;
    openModal('delModal');
}

document.querySelectorAll('.backdrop').forEach(b => {
    b.addEventListener('click', e => { if (e.target === b) b.classList.remove('open'); });
});
document.addEventListener('keydown', e => {
    if (e.key === 'Escape') document.querySelectorAll('.backdrop.open').forEach(b => b.classList.remove('open'));
});
</script>
</body>
</html>
