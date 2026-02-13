<?php
/**
 * Professional PHP File Manager
 * Single-file implementation with authentication and security features
 * Version: 1.0
 */

// ============================================================================
// CONFIGURATION - Modify these settings as needed
// ============================================================================

define('FM_PASSWORD', 'bela'); // Change this password immediately after first use
define('FM_SESSION_TIMEOUT', 3600); // Session timeout in seconds (1 hour)
define('FM_ROOT_PATH', dirname(__FILE__)); // Starting directory
define('FM_SHOW_HIDDEN', false); // Show hidden files and folders
define('FM_ALLOWED_EXTENSIONS', 'txt,php,html,css,js,json,xml,htaccess,md,log,sql,csv,ini,conf,yml,yaml,hpp,cpp,c,h,py,sh,bat'); // Allowed file extensions
define('FM_MAX_UPLOAD_SIZE_MB', 50); // Maximum upload size in MB
define('FM_ALLOW_SYSTEM_WIDE', true); // Enable system-wide directory access

// ============================================================================
// SECURITY HELPER CLASS
// ============================================================================

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
            if ($checkPath === false || strpos($checkPath, $rootPath) !== 0) {
                return false;
            }
        }
        return true;
    }
    
    public static function setSecurityHeaders() {
        header('X-Frame-Options: SAMEORIGIN');
        header('X-Content-Type-Options: nosniff');
        header('X-XSS-Protection: 1; mode=block');
    }
}

// ============================================================================
// AUTHENTICATION CLASS
// ============================================================================

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

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

function formatSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= (1 << (10 * $pow));
    return round($bytes, 2) . ' ' . $units[$pow];
}

function getFileIcon($isDir, $filename) {
    if ($isDir) return '📁';
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $icons = [
        'php' => '🐘', 'html' => '🌐', 'css' => '🎨', 'js' => '⚡',
        'json' => '📋', 'xml' => '📄', 'txt' => '📝', 'md' => '📖',
        'log' => '📊', 'sql' => '🗄️', 'csv' => '📈', 'ini' => '⚙️',
        'yml' => '⚙️', 'yaml' => '⚙️', 'conf' => '⚙️'
    ];
    return $icons[$ext] ?? '📄';
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

// ============================================================================
// MAIN APPLICATION LOGIC
// ============================================================================

SecurityHelper::setSecurityHeaders();
FileManagerAuth::startSession();

// Handle logout
if (isset($_GET['logout'])) {
    FileManagerAuth::logout();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// Handle login
if (!FileManagerAuth::isAuthenticated()) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
        if (FileManagerAuth::login($_POST['password'])) {
            header('Location: ' . $_SERVER['PHP_SELF']);
            exit;
        } else {
            $loginError = 'Invalid password';
        }
    }
    
    // Display login page
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>File Manager - Login</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); height: 100vh; display: flex; align-items: center; justify-content: center; }
            .login-box { background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); width: 350px; }
            h2 { color: #667eea; margin-bottom: 30px; text-align: center; }
            input { width: 100%; padding: 12px; margin-bottom: 20px; border: 2px solid #e0e0e0; border-radius: 5px; font-size: 14px; }
            input:focus { outline: none; border-color: #667eea; }
            button { width: 100%; padding: 12px; background: #667eea; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; }
            button:hover { background: #5568d3; }
            .error { background: #fee; color: #c33; padding: 10px; border-radius: 5px; margin-bottom: 15px; text-align: center; }
        </style>
    </head>
    <body>
        <div class="login-box">
            <h2>🔐 File Manager</h2>
            <?php if (isset($loginError)): ?>
                <div class="error"><?php echo htmlspecialchars($loginError); ?></div>
            <?php endif; ?>
            <form method="POST">
                <input type="password" name="password" placeholder="Enter password" required autofocus>
                <button type="submit">Login</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Initialize variables
$currentPath = FM_ROOT_PATH;
$message = '';
$messageType = '';

// Handle directory navigation
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

// Handle POST operations
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !SecurityHelper::validateCSRFToken($_POST['csrf_token'])) {
        $message = 'Security token validation failed';
        $messageType = 'error';
    } else {
        // Upload file
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
        
        // Create folder
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
        
        // Create file
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
        
        // Rename
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
        
        // Delete
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
        
        // Save file content
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

// Handle file download
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

// Handle file editing
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
            <title>Edit File - <?php echo htmlspecialchars(basename($editFile)); ?></title>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { font-family: Arial, sans-serif; background: #f5f5f5; }
                .editor-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; }
                .editor-header h2 { margin-bottom: 10px; }
                .editor-info { font-size: 13px; opacity: 0.9; }
                .editor-container { padding: 20px; }
                textarea { width: 100%; height: calc(100vh - 200px); padding: 15px; border: 2px solid #ddd; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 14px; resize: none; }
                .btn-group { margin-top: 15px; display: flex; gap: 10px; }
                button { padding: 12px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 14px; }
                .btn-save { background: #28a745; color: white; }
                .btn-save:hover { background: #218838; }
                .btn-back { background: #6c757d; color: white; }
                .btn-back:hover { background: #5a6268; }
            </style>
        </head>
        <body>
            <div class="editor-header">
                <h2>📝 Editing: <?php echo htmlspecialchars(basename($editFile)); ?></h2>
                <div class="editor-info">
                    Path: <?php echo htmlspecialchars($editFile); ?> | 
                    Size: <?php echo formatSize($fileSize); ?> | 
                    Modified: <?php echo htmlspecialchars($lastModified); ?>
                </div>
            </div>
            <div class="editor-container">
                <form method="POST" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($editFile))); ?>">
                    <input type="hidden" name="csrf_token" value="<?php echo SecurityHelper::generateCSRFToken(); ?>">
                    <input type="hidden" name="file_path" value="<?php echo htmlspecialchars($editFile); ?>">
                    <textarea name="file_content"><?php echo htmlspecialchars($fileContent); ?></textarea>
                    <div class="btn-group">
                        <button type="submit" name="save_file" class="btn-save">💾 Save File</button>
                        <a href="<?php echo htmlspecialchars($_SERVER['PHP_SELF'] . '?path=' . urlencode(dirname($editFile))); ?>">
                            <button type="button" class="btn-back">← Back to Directory</button>
                        </a>
                    </div>
                </form>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}

// Get directory contents
$items = [];
if (is_readable($currentPath)) {
    $scanItems = scandir($currentPath);
    foreach ($scanItems as $item) {
        if ($item === '.' || (!FM_SHOW_HIDDEN && $item[0] === '.' && $item !== '..')) {
            continue;
        }
        
        $itemPath = $currentPath . '/' . $item;
        $isDir = is_dir($itemPath);
        $items[] = [
            'name' => $item,
            'is_dir' => $isDir,
            'size' => $isDir ? '-' : formatSize(filesize($itemPath)),
            'modified' => date('Y-m-d H:i:s', filemtime($itemPath)),
            'permissions' => substr(sprintf('%o', fileperms($itemPath)), -4)
        ];
    }
}

// Generate breadcrumb
$pathParts = explode('/', str_replace('\\', '/', $currentPath));
$breadcrumb = [];
$cumulativePath = '';
foreach ($pathParts as $part) {
    if ($part === '') continue;
    $cumulativePath .= '/' . $part;
    $breadcrumb[] = ['name' => $part, 'path' => $cumulativePath];
}

// Get user directories
$userDirs = getUserDirectories();

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>File Manager</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: Arial, sans-serif; background: #f5f5f5; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; margin-bottom: 5px; }
        .header-info { font-size: 13px; opacity: 0.9; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .current-path { background: #e8f5e9; border-left: 4px solid #4caf50; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .current-path strong { font-family: 'Courier New', monospace; font-size: 15px; color: #2e7d32; }
        .breadcrumb { background: #f0f0f0; padding: 12px 15px; margin-bottom: 20px; border-radius: 5px; font-size: 14px; }
        .breadcrumb a { color: #667eea; text-decoration: none; margin: 0 5px; }
        .breadcrumb a:hover { text-decoration: underline; }
        .breadcrumb span { color: #999; margin: 0 5px; }
        .path-input { margin-bottom: 20px; }
        .path-input input { width: 100%; padding: 12px; border: 2px solid #667eea; border-radius: 5px; font-size: 14px; font-family: 'Courier New', monospace; }
        .quick-nav { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .quick-nav button { padding: 10px 20px; border: none; border-radius: 5px; background: #667eea; color: white; cursor: pointer; font-size: 13px; }
        .quick-nav button:hover { background: #5568d3; }
        .quick-nav button.active { background: #4caf50; }
        .actions { display: flex; gap: 10px; margin-bottom: 20px; flex-wrap: wrap; }
        .btn { padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; font-size: 14px; text-decoration: none; display: inline-block; }
        .btn-primary { background: #667eea; color: white; }
        .btn-primary:hover { background: #5568d3; }
        .btn-success { background: #28a745; color: white; }
        .btn-success:hover { background: #218838; }
        .btn-danger { background: #dc3545; color: white; }
        .btn-danger:hover { background: #c82333; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #5a6268; }
        .message { padding: 15px; margin-bottom: 20px; border-radius: 5px; }
        .message.success { background: #d4edda; color: #155724; border-left: 4px solid #28a745; }
        .message.error { background: #f8d7da; color: #721c24; border-left: 4px solid #dc3545; }
        .file-table { background: white; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #f8f9fa; padding: 15px; text-align: left; font-weight: 600; color: #495057; border-bottom: 2px solid #dee2e6; }
        td { padding: 12px 15px; border-bottom: 1px solid #dee2e6; }
        tr:hover { background: #f8f9fa; }
        .icon { font-size: 20px; margin-right: 8px; }
        .file-name { display: flex; align-items: center; }
        .file-name a { color: #667eea; text-decoration: none; }
        .file-name a:hover { text-decoration: underline; }
        .action-btns { display: flex; gap: 5px; }
        .action-btns button { padding: 6px 12px; font-size: 12px; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); align-items: center; justify-content: center; z-index: 1000; }
        .modal.active { display: flex; }
        .modal-content { background: white; padding: 30px; border-radius: 10px; max-width: 500px; width: 90%; }
        .modal-content h3 { margin-bottom: 20px; color: #333; }
        .modal-content input { width: 100%; padding: 10px; margin-bottom: 15px; border: 2px solid #ddd; border-radius: 5px; }
        .modal-content .btn { margin-right: 10px; }
        .empty-state { text-align: center; padding: 60px 20px; color: #999; }
        .empty-state .icon { font-size: 60px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>📂 File Manager</h1>
        <div class="header-info">
            User: <?php echo htmlspecialchars(get_current_user()); ?> | 
            Session: <?php echo gmdate('H:i:s', time() - $_SESSION['login_time']); ?> | 
            <a href="?logout" style="color: white;">Logout</a>
        </div>
    </div>
    
    <div class="container">
        <?php if ($message): ?>
            <div class="message <?php echo $messageType; ?>"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>
        
        <div class="current-path">
            <strong>📍 Current Path: <?php echo htmlspecialchars($currentPath); ?></strong>
        </div>
        
        <div class="breadcrumb">
            <a href="?path=/">🏠 Root</a>
            <?php foreach ($breadcrumb as $crumb): ?>
                <span>/</span>
                <a href="?path=<?php echo urlencode($crumb['path']); ?>"><?php echo htmlspecialchars($crumb['name']); ?></a>
            <?php endforeach; ?>
        </div>
        
        <div class="path-input">
            <form method="GET">
                <input type="text" name="path" placeholder="Type path and press Enter (e.g., /home/user or /var/www)" value="<?php echo htmlspecialchars($currentPath); ?>">
            </form>
        </div>
        
        <div class="quick-nav">
            <form method="GET" style="display: inline;">
                <button type="submit" name="path" value="/" class="<?php echo $currentPath === '/' ? 'active' : ''; ?>">🏠 Root</button>
            </form>
            <form method="GET" style="display: inline;">
                <button type="submit" name="path" value="/home" class="<?php echo $currentPath === '/home' ? 'active' : ''; ?>">👤 Home</button>
            </form>
            <form method="GET" style="display: inline;">
                <button type="submit" name="path" value="<?php echo FM_ROOT_PATH; ?>" class="<?php echo $currentPath === realpath(FM_ROOT_PATH) ? 'active' : ''; ?>">📂 Script Dir</button>
            </form>
            <?php foreach ($userDirs as $userDir): ?>
                <form method="GET" style="display: inline;">
                    <button type="submit" name="path" value="<?php echo htmlspecialchars($userDir); ?>" class="<?php echo $currentPath === realpath($userDir) ? 'active' : ''; ?>">
                        👤 <?php echo htmlspecialchars(basename($userDir)); ?>
                    </button>
                </form>
            <?php endforeach; ?>
        </div>
        
        <div class="actions">
            <button onclick="showModal('uploadModal')" class="btn btn-primary">⬆️ Upload File</button>
            <button onclick="showModal('createFolderModal')" class="btn btn-success">📁 New Folder</button>
            <button onclick="showModal('createFileModal')" class="btn btn-success">📄 New File</button>
        </div>
        
        <div class="file-table">
            <?php if (empty($items)): ?>
                <div class="empty-state">
                    <div class="icon">📭</div>
                    <p>This folder is empty</p>
                </div>
            <?php else: ?>
                <table>
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Size</th>
                            <th>Modified</th>
                            <th>Permissions</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($items as $item): ?>
                            <tr>
                                <td>
                                    <div class="file-name">
                                        <span class="icon"><?php echo getFileIcon($item['is_dir'], $item['name']); ?></span>
                                        <?php if ($item['is_dir']): ?>
                                            <a href="?path=<?php echo urlencode($currentPath . '/' . $item['name']); ?>">
                                                <?php echo htmlspecialchars($item['name']); ?>
                                            </a>
                                        <?php else: ?>
                                            <?php echo htmlspecialchars($item['name']); ?>
                                        <?php endif; ?>
                                    </div>
                                </td>
                                <td><?php echo htmlspecialchars($item['size']); ?></td>
                                <td><?php echo htmlspecialchars($item['modified']); ?></td>
                                <td><?php echo htmlspecialchars($item['permissions']); ?></td>
                                <td>
                                    <div class="action-btns">
                                        <?php if (!$item['is_dir'] && isEditableFile($item['name'])): ?>
                                            <a href="?path=<?php echo urlencode($currentPath); ?>&edit=<?php echo urlencode($item['name']); ?>">
                                                <button class="btn btn-primary">✏️ Edit</button>
                                            </a>
                                        <?php endif; ?>
                                        <?php if (!$item['is_dir']): ?>
                                            <a href="?path=<?php echo urlencode($currentPath); ?>&download=<?php echo urlencode($item['name']); ?>">
                                                <button class="btn btn-success">⬇️ Download</button>
                                            </a>
                                        <?php endif; ?>
                                        <?php if ($item['name'] !== '..' && $item['name'] !== '.'): ?>
                                            <button onclick="showRenameModal('<?php echo htmlspecialchars($item['name']); ?>')" class="btn btn-secondary">✏️ Rename</button>
                                            <button onclick="showDeleteModal('<?php echo htmlspecialchars($item['name']); ?>')" class="btn btn-danger">🗑️ Delete</button>
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
    
    <!-- Upload Modal -->
    <div id="uploadModal" class="modal">
        <div class="modal-content">
            <h3>⬆️ Upload File</h3>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?php echo SecurityHelper::generateCSRFToken(); ?>">
                <input type="file" name="upload_file" required>
                <div>
                    <button type="submit" class="btn btn-primary">Upload</button>
                    <button type="button" onclick="hide
