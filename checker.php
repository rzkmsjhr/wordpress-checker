<?php
/**
 * Standalone WordPress & PHP Security Health Check (SFTP Edition)
 * Upload to WordPress root (alongside wp-config.php), view in browser, then click "Delete This Script".
 */

// 1. Optional: Set a secret key so only you can view it (e.g., yoursite.com/wp-security-check.php?key=check123)
$access_key = 'check123'; 

if (!isset($_GET['key']) || $_GET['key'] !== $access_key) {
    http_response_code(403);
    die('403 Forbidden: Append ?key=' . htmlspecialchars($access_key) . ' to the URL to view the report.');
}

// 2. Self-destruct handler
if (isset($_POST['self_destruct']) && $_POST['self_destruct'] === '1') {
    if (@unlink(__FILE__)) {
        die('<div style="font-family:sans-serif;padding:40px;text-align:center;"><h2 style="color:#16a34a;">Script Deleted Successfully</h2><p>wp-security-check.php has been removed from your server.</p></div>');
    } else {
        $destruct_error = 'Could not auto-delete due to file permissions. Please delete this file manually via SFTP.';
    }
}

// --- CHECK 1: PHP Version against Oct 2026 Security Patch Baseline ---
$current_php = PHP_VERSION;
$major_minor = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$patched_baselines = [
    '8.1' => '8.1.34',
    '8.2' => '8.2.35',
    '8.3' => '8.3.36',
    '8.4' => '8.4.27',
    '8.5' => '8.5.12',
];

$php_status = 'WARN';
$php_msg = '';

if (version_compare($major_minor, '8.1', '<')) {
    $php_status = 'FAIL';
    $php_msg = "PHP $current_php is End-of-Life (EOL) and no longer receives upstream security patches.";
} elseif (isset($patched_baselines[$major_minor])) {
    $req = $patched_baselines[$major_minor];
    if (version_compare($current_php, $req, '>=')) {
        $php_status = 'PASS';
        $php_msg = "PHP $current_php is up to date and meets or exceeds the patched baseline ($req).";
    } else {
        $php_status = 'FAIL';
        $php_msg = "PHP $current_php is vulnerable. Minimum patched version for PHP $major_minor is $req.";
    }
}

// --- CHECK 2: In-Memory Binary Check (/proc/self/maps) ---
$mem_status = 'INFO';
$mem_msg = 'Restricted by shared hosting (open_basedir / OS permissions).';
if (@is_readable('/proc/self/maps')) {
    $maps = @file_get_contents('/proc/self/maps');
    if ($maps !== false) {
        if (preg_match('/php.*\(deleted\)/i', $maps)) {
            $mem_status = 'WARN';
            $mem_msg = 'Old PHP binary still mapped in RAM ((deleted) flag detected). PHP-FPM/LSAPI needs a reload.';
        } else {
            $mem_status = 'PASS';
            $mem_msg = 'Active worker process is running the current binary from disk (no stale deleted maps).';
        }
    }
}

// --- CHECK 3: Dangerous Shell Execution Functions ---
$dangerous_funcs = ['exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'popen'];
$enabled_funcs = [];
$disabled_ini = array_map('trim', explode(',', (string)ini_get('disable_functions')));

foreach ($dangerous_funcs as $fn) {
    if (function_exists($fn) && !in_array($fn, $disabled_ini, true)) {
        $enabled_funcs[] = $fn;
    }
}
$func_status = empty($enabled_funcs) ? 'PASS' : 'WARN';
$func_msg = empty($enabled_funcs)
    ? 'All command execution functions (exec, shell_exec, system, etc.) are disabled.'
    : 'Enabled shell functions: ' . implode(', ', $enabled_funcs) . ' (Common on some hosts, but increases RCE impact).';

// --- CHECK 4: Suspicious PHP Files in wp-content/uploads ---
$uploads_dir = __DIR__ . '/wp-content/uploads';
$uploads_php = [];
if (is_dir($uploads_dir)) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($uploads_dir, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if ($file->isFile() && preg_match('/\.(php\d?|phtml|phar|sh|pl|py|cgi)$/i', $file->getFilename())) {
            $uploads_php[] = str_replace(__DIR__ . '/', '', $file->getPathname());
            if (count($uploads_php) >= 50) break;
        }
    }
}
$uploads_status = empty($uploads_php) ? 'PASS' : 'FAIL';

// --- CHECK 5: wp-config.php & index.php Signature Scan ---
$core_alerts = [];
foreach (['wp-config.php', 'index.php'] as $core_file) {
    $full_path = __DIR__ . '/' . $core_file;
    if (is_readable($full_path)) {
        $content = @file_get_contents($full_path);
        if (preg_match('/(eval\s*\(|base64_decode\s*\(|gzinflate\s*\(|str_rot13\s*\(|\\x[0-9a-f]{2}.*\\x[0-9a-f]{2})/i', $content)) {
            $core_alerts[] = "$core_file contains obfuscated code or suspicious functions (eval/base64/hex).";
        }
    }
}
$core_status = empty($core_alerts) ? 'PASS' : 'FAIL';

// --- CHECK 6: Recently Modified PHP Files (Last 72 Hours) ---
$recent_files = [];
$cutoff = time() - (72 * 3600);
$self_name = basename(__FILE__);

try {
    $dir_iter = new RecursiveDirectoryIterator(__DIR__, RecursiveDirectoryIterator::SKIP_DOTS);
    $filter_iter = new RecursiveCallbackFilterIterator($dir_iter, function ($current) {
        $skip = ['cache', 'wflogs', 'litespeed', 'node_modules', '.git'];
        return !($current->isDir() && in_array($current->getFilename(), $skip, true));
    });
    $flat_iter = new RecursiveIteratorIterator($filter_iter);

    foreach ($flat_iter as $file) {
        if ($file->isFile() && $file->getFilename() !== $self_name) {
            if (preg_match('/\.(php\d?|phtml|phar)$/i', $file->getFilename()) && $file->getMTime() >= $cutoff) {
                $recent_files[] = [
                    'path' => str_replace(__DIR__ . '/', '', $file->getPathname()),
                    'time' => date('Y-m-d H:i:s', $file->getMTime()),
                ];
                if (count($recent_files) >= 40) break;
            }
        }
    }
} catch (Exception $e) {
    // Ignore unreadable subdirectories
}

// --- CHECK 7: Temp Directory Inspection (If accessible) ---
$temp_alerts = [];
$temp_dirs = array_unique(['/tmp', '/var/tmp', '/dev/shm', sys_get_temp_dir()]);
foreach ($temp_dirs as $tdir) {
    if (@is_dir($tdir) && @is_readable($tdir)) {
        $items = @scandir($tdir);
        if (is_array($items)) {
            foreach ($items as $item) {
                if ($item === '.' || $item === '..') continue;
                $full = rtrim($tdir, '/') . '/' . $item;
                if (@is_file($full) && (preg_match('/\.(sh|elf|py|pl|php)$/i', $item) || @is_executable($full))) {
                    $temp_alerts[] = $full;
                }
            }
        }
    }
}
$temp_status = empty($temp_alerts) ? 'PASS' : 'WARN';

function badge($status) {
    $colors = [
        'PASS' => 'background:#dcfce7;color:#166534;border:1px solid #86efac;',
        'WARN' => 'background:#fef9c3;color:#854d0e;border:1px solid #fde047;',
        'FAIL' => 'background:#fee2e2;color:#991b1b;border:1px solid #fca5a5;',
        'INFO' => 'background:#e0f2fe;color:#075985;border:1px solid #7dd3fc;',
    ];
    $style = isset($colors[$status]) ? $colors[$status] : $colors['INFO'];
    return "<span style='padding:3px 10px;border-radius:99px;font-size:12px;font-weight:700;$style'>$status</span>";
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Server & WordPress Security Audit</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #1e293b; margin: 0; padding: 30px; }
        .container { max-width: 900px; margin: 0 auto; background: #fff; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.06); padding: 28px; }
        h1 { margin-top: 0; font-size: 22px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #e2e8f0; padding-bottom: 16px; }
        .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; background: #f1f5f9; padding: 14px; border-radius: 8px; font-size: 13px; margin-bottom: 24px; }
        .card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 14px; }
        .card-header { display: flex; justify-content: space-between; align-items: center; font-weight: 600; margin-bottom: 8px; }
        .card-body { font-size: 14px; color: #475569; line-height: 1.5; }
        ul.file-list { background: #0f172a; color: #f8fafc; padding: 12px 12px 12px 30px; border-radius: 6px; font-family: monospace; font-size: 12px; max-height: 200px; overflow-y: auto; margin: 8px 0 0; }
        .btn-delete { background: #dc2626; color: #fff; border: none; padding: 9px 16px; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 13px; }
        .btn-delete:hover { background: #b91c1c; }
    </style>
</head>
<body>
<div class="container">
    <h1>
        <span>Server & WP Security Diagnostic</span>
        <form method="POST" style="margin:0;" onsubmit="return confirm('Delete this script from the server now?');">
            <input type="hidden" name="self_destruct" value="1">
            <button type="submit" class="btn-delete">Delete This Script Now</button>
        </form>
    </h1>

    <?php if (!empty($destruct_error)): ?>
        <p style="color:#dc2626;font-weight:bold;"><?= htmlspecialchars($destruct_error) ?></p>
    <?php endif; ?>

    <div class="meta">
        <div><strong>Host:</strong> <?= htmlspecialchars($_SERVER['HTTP_HOST'] ?? 'Unknown') ?></div>
        <div><strong>Server IP:</strong> <?= htmlspecialchars($_SERVER['SERVER_ADDR'] ?? gethostbyname($_SERVER['HTTP_HOST'] ?? '')) ?></div>
        <div><strong>Web Server:</strong> <?= htmlspecialchars($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') ?></div>
        <div><strong>SAPI:</strong> <?= htmlspecialchars(php_sapi_name()) ?></div>
    </div>

    <div class="card">
        <div class="card-header"><span>1. PHP Runtime & Patch Level</span> <?= badge($php_status) ?></div>
        <div class="card-body"><?= htmlspecialchars($php_msg) ?></div>
    </div>

    <div class="card">
        <div class="card-header"><span>2. Process Memory Binary Check</span> <?= badge($mem_status) ?></div>
        <div class="card-body"><?= htmlspecialchars($mem_msg) ?></div>
    </div>

    <div class="card">
        <div class="card-header"><span>3. Executable Scripts in wp-content/uploads</span> <?= badge($uploads_status) ?></div>
        <div class="card-body">
            <?php if (empty($uploads_php)): ?>
                No executable PHP or shell scripts found inside <code>wp-content/uploads</code>.
            <?php else: ?>
                Suspicious executable files detected inside the uploads directory:
                <ul class="file-list">
                    <?php foreach ($uploads_php as $f): ?><li><?= htmlspecialchars($f) ?></li><?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    </div>

    <div class="card">
        <div class="card-header"><span>4. Core Entrypoint Integrity (wp-config.php & index.php)</span> <?= badge($core_status) ?></div>
        <div class="card-body">
            <?php if (empty($core_alerts)): ?>
                No obfuscated malware signatures (eval, base64_decode, gzinflate) detected in core entry files.
            <?php else: ?>
                <ul class="file-list">
                    <?php foreach ($core_alerts as $a): ?><li><?= htmlspecialchars($a) ?></li><?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    </div>

    <div class="card">
        <div class="card-header"><span>5. PHP Shell Execution Functions</span> <?= badge($func_status) ?></div>
        <div class="card-body"><?= htmlspecialchars($func_msg) ?></div>
    </div>

    <div class="card">
        <div class="card-header"><span>6. Temp Directory Executables (/tmp, /dev/shm)</span> <?= badge($temp_status) ?></div>
        <div class="card-body">
            <?php if (empty($temp_alerts)): ?>
                No suspicious executable binaries or scripts visible in accessible temporary directories.
            <?php else: ?>
                Files flagged in temporary folders:
                <ul class="file-list">
                    <?php foreach ($temp_alerts as $t): ?><li><?= htmlspecialchars($t) ?></li><?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <span>7. Recently Modified PHP Files (Last 72 Hours)</span>
            <?= badge(empty($recent_files) ? 'PASS' : 'INFO') ?>
        </div>
        <div class="card-body">
            <?php if (empty($recent_files)): ?>
                No PHP files have been modified in the last 72 hours.
            <?php else: ?>
                Review these recently modified PHP files (normal if you updated plugins/themes recently):
                <ul class="file-list">
                    <?php foreach ($recent_files as $rf): ?>
                        <li>[<?= htmlspecialchars($rf['time']) ?>] <?= htmlspecialchars($rf['path']) ?></li>
                    <?php endforeach; ?>
                </ul>
            <?php endif; ?>
        </div>
    </div>
</div>
</body>
</html>