<?php
define('RACORE_ROOT', dirname(__FILE__));
define('RACORE_VERSION', '4.1');
define('RACORE_LICENSE_KEY', 'RACORE-' . md5('secure_hash_platform_2024_prod'));

error_reporting(0);
ini_set('display_errors', 0);
ini_set('log_errors', 0);

require_once 'racore-license.php';
require_once 'racore-core.php';

if (!RacoreLicense::verify()) {
    header('HTTP/1.1 403 Forbidden');
    header('Content-Type: text/html; charset=utf-8');
    die('
        <!DOCTYPE html>
        <html>
        <head>
            <title>Giriş Qadağandır - RACORE Təhlükəsizlik</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body { font-family: Arial, sans-serif; background: #f8f9fa; color: #dc3545; text-align: center; padding: 50px; }
                .error-box { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 600px; margin: 0 auto; }
                .logo { color: #2563eb; font-weight: bold; font-size: 1.5em; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <div class="error-box">
                <div class="logo">RACORE TƏHLÜKƏSİZLİK</div>
                <h1>🚫 GİRİŞ QADAĞANDIR</h1>
                <p>Təhlükəsizlik pozuntusu aşkarlandı.</p>
                <p>Yanlış lisenziya və ya müdaxilə aşkarlandı.</p>
                <hr>
                <small>RACORE Təhlükəsizlik Sistemi v4.1</small>
            </div>
        </body>
        </html>
    ');
}

$result = [];
$show_result = false;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $racore = new RacoreCore();
        
        if (!$racore->checkRateLimit()) {
            $result = [
                'status' => 'error',
                'message' => 'Çox sayda sorğu. Yenidən cəhd etmədən əvvəl gözləyin.'
            ];
        } else {
            $result = $racore->processRequest($_POST);
        }
        $show_result = true;
    } catch (Exception $e) {
        $result = [
            'status' => 'error',
            'message' => 'Sorğunuzu emal edərkən xəta baş verdi.'
        ];
        $show_result = true;
    }
}

$stats = [];
if (class_exists('RacoreCore')) {
    $racore = new RacoreCore();
    $stats = $racore->getStatistics();
}
?>
<!DOCTYPE html>
<html lang="az">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="RACORE Təhlükəsiz Hash & Şifrələmə Platforması">
    <meta name="author" content="RACORE Technologies">
    <title>RACORE Təhlükəsiz Hash & Şifrələmə Platforması</title>
    
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; style-src 'self' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; script-src 'self' 'unsafe-inline'">
    
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    
    <link rel="stylesheet" href="styles/racore-main.css?v=4.1">
</head>
<body>
    <div class="racore-nav-buttons">
        <button class="racore-nav-btn racore-nav-up" onclick="scrollToTop()">
            <i class="fas fa-chevron-up"></i>
        </button>
        <button class="racore-nav-btn racore-nav-down" onclick="scrollToBottom()">
            <i class="fas fa-chevron-down"></i>
        </button>
    </div>

    <header class="racore-header">
        <div class="racore-container">
            <div class="racore-logo">
                <i class="fas fa-shield-alt"></i>
                <span>RACORE TƏHLÜKƏSİZLİK</span>
            </div>
            <div class="racore-version">v<?php echo RACORE_VERSION; ?></div>
        </div>
    </header>

    <main class="racore-main">
        <div class="racore-container">
            <div class="racore-hero">
                <h1 class="racore-title">Şifrə Hashləmə & Şifrələmə Platforması</h1>
                <p class="racore-subtitle">RACORE tərəfindən qorunan yüksək təhlükəsizlikli həll</p>
            </div>

            <?php if ($show_result && !empty($result) && isset($result['status'])): ?>
            <div class="racore-result <?php echo $result['status']; ?>">
                <div class="racore-result-header">
                    <i class="fas fa-<?php echo $result['status'] === 'success' ? 'check' : 'exclamation'; ?>-circle"></i>
                    <span>Nəticə</span>
                </div>
                <div class="racore-result-content">
                    <pre><?php echo htmlspecialchars($result['message'] ?? ''); ?></pre>
                    <?php if (isset($result['hash'])): ?>
                    <div class="racore-hash-result">
                        <strong>Nəticə:</strong> 
                        <div class="racore-hash-output">
                            <code id="hash-output"><?php echo htmlspecialchars($result['hash']); ?></code>
                            <button class="racore-copy-btn" onclick="racoreCopyToClipboard('hash-output')">
                                <i class="fas fa-copy"></i> Kopyala
                            </button>
                        </div>
                    </div>
                    <?php endif; ?>
                    <?php if (isset($result['details'])): ?>
                    <div class="racore-details">
                        <strong>Əlavə Məlumat:</strong>
                        <pre><?php echo htmlspecialchars($result['details']); ?></pre>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
            <?php endif; ?>

            <div class="racore-grid">
                <div class="racore-card">
                    <div class="racore-card-header">
                        <i class="fas fa-fingerprint"></i>
                        <h3>Hashləmə Alqoritmləri</h3>
                    </div>
                    <form method="POST" class="racore-form" id="hash-form">
                        <input type="hidden" name="action" value="hash">
                        <input type="hidden" name="csrf_token" value="<?php echo $racore->generateCSRFToken(); ?>">
                        
                        <div class="racore-form-group">
                            <label for="password">Şifrə:</label>
                            <input type="password" id="password" name="password" required 
                                   placeholder="Hashləmək üçün şifrə daxil edin"
                                   minlength="1" maxlength="255">
                            <div class="racore-password-strength" id="password-strength">
                                <div class="racore-strength-bar"></div>
                                <div class="racore-strength-text"></div>
                            </div>
                        </div>

                        <div class="racore-form-group">
                            <label for="algorithm">Alqoritm Seçin:</label>
                            <select id="algorithm" name="algorithm" required>
                                <option value="bcrypt">BCRYPT</option>
                                <?php if (defined('PASSWORD_ARGON2I')): ?>
                                <option value="argon2i">ARGON2I</option>
                                <?php endif; ?>
                                <?php if (defined('PASSWORD_ARGON2ID')): ?>
                                <option value="argon2id">ARGON2ID</option>
                                <?php endif; ?>
                                <option value="sha256">SHA256</option>
                                <option value="sha512">SHA512</option>
                                <option value="sha3-256">SHA3-256</option>
                                <option value="sha3-512">SHA3-512</option>
                                <option value="whirlpool">Whirlpool</option>
                            </select>
                        </div>

                        <div class="racore-form-group">
                            <label for="cost">Mürəkkəblik (Cost): <span id="cost-value">12</span></label>
                            <input type="range" id="cost" name="cost" min="4" max="31" value="12"
                                   oninput="document.getElementById('cost-value').textContent = this.value">
                        </div>

                        <button type="submit" class="racore-btn racore-btn-primary" id="hash-submit">
                            <i class="fas fa-hashtag"></i>
                            Hash Yarat
                        </button>
                    </form>
                </div>

                <div class="racore-card">
                    <div class="racore-card-header">
                        <i class="fas fa-lock"></i>
                        <h3>Şifrələmə Alqoritmləri</h3>
                    </div>
                    <form method="POST" class="racore-form" id="encrypt-form">
                        <input type="hidden" name="action" value="encrypt">
                        <input type="hidden" name="csrf_token" value="<?php echo $racore->generateCSRFToken(); ?>">
                        
                        <div class="racore-form-group">
                            <label for="data">Mətn:</label>
                            <textarea id="data" name="data" required 
                                      placeholder="Şifrələmək və ya deşifrələmək üçün mətn daxil edin" 
                                      rows="3" maxlength="10000"></textarea>
                        </div>

                        <div class="racore-form-group">
                            <label for="encryption_key">Açar:</label>
                            <input type="password" id="encryption_key" name="encryption_key" required 
                                   placeholder="Şifrələmə açarı" minlength="1" maxlength="255">
                        </div>

                        <div class="racore-form-group">
                            <label for="encryption_method">Metod:</label>
                            <select id="encryption_method" name="encryption_method" required>
                                <option value="aes-256-cbc">AES-256-CBC</option>
                                <option value="aes-128-cbc">AES-128-CBC</option>
                                <option value="aes-256-gcm">AES-256-GCM</option>
                                <option value="aes-128-gcm">AES-128-GCM</option>
                                <option value="chacha20-poly1305">ChaCha20-Poly1305</option>
                                <option value="bf-cbc">Blowfish</option>
                            </select>
                        </div>

                        <div class="racore-form-actions">
                            <button type="submit" name="operation" value="encrypt" 
                                    class="racore-btn racore-btn-success">
                                <i class="fas fa-lock"></i>
                                Şifrələ
                            </button>
                            <button type="submit" name="operation" value="decrypt" 
                                    class="racore-btn racore-btn-warning">
                                <i class="fas fa-unlock"></i>
                                Deşifrələ
                            </button>
                        </div>
                    </form>
                </div>

                <div class="racore-card">
                    <div class="racore-card-header">
                        <i class="fas fa-check-double"></i>
                        <h3>Hash Yoxlama</h3>
                    </div>
                    <form method="POST" class="racore-form" id="verify-form">
                        <input type="hidden" name="action" value="verify">
                        <input type="hidden" name="csrf_token" value="<?php echo $racore->generateCSRFToken(); ?>">
                        
                        <div class="racore-form-group">
                            <label for="verify_password">Şifrə:</label>
                            <input type="password" id="verify_password" name="verify_password" required 
                                   placeholder="Yoxlamaq üçün şifrə daxil edin">
                        </div>

                        <div class="racore-form-group">
                            <label for="verify_hash">Hash:</label>
                            <textarea id="verify_hash" name="verify_hash" required 
                                      placeholder="Hash daxil edin" rows="3"></textarea>
                        </div>

                        <button type="submit" class="racore-btn racore-btn-info">
                            <i class="fas fa-check-circle"></i>
                            Hash Yoxla
                        </button>
                    </form>
                </div>

                <div class="racore-card">
                    <div class="racore-card-header">
                        <i class="fas fa-key"></i>
                        <h3>Təsadüfi Açar Generatoru</h3>
                    </div>
                    <form method="POST" class="racore-form" id="keygen-form">
                        <input type="hidden" name="action" value="keygen">
                        <input type="hidden" name="csrf_token" value="<?php echo $racore->generateCSRFToken(); ?>">
                        
                        <div class="racore-form-group">
                            <label for="key_length">Açar Uzunluğu (bayt):</label>
                            <input type="range" id="key_length" name="key_length" min="16" max="64" value="32">
                            <span id="key-length-value">32</span>
                        </div>

                        <div class="racore-form-group">
                            <label for="key_format">Format:</label>
                            <select id="key_format" name="key_format">
                                <option value="hex">Hex</option>
                                <option value="base64">Base64</option>
                                <option value="base64url">Base64 URL Safe</option>
                            </select>
                        </div>

                        <button type="submit" class="racore-btn racore-btn-secondary">
                            <i class="fas fa-sync"></i>
                            Açar Yaradın
                        </button>
                    </form>
                </div>

                <div class="racore-card">
                    <div class="racore-card-header">
                        <i class="fas fa-user-lock"></i>
                        <h3>Güclü Parol Generatoru</h3>
                    </div>
                    <form method="POST" class="racore-form" id="passwordgen-form">
                        <input type="hidden" name="action" value="passwordgen">
                        <input type="hidden" name="csrf_token" value="<?php echo $racore->generateCSRFToken(); ?>">
                        
                        <div class="racore-form-group">
                            <label for="password_length">Parol Uzunluğu:</label>
                            <input type="range" id="password_length" name="password_length" min="8" max="64" value="16">
                            <span id="password-length-value">16</span>
                        </div>

                        <div class="racore-form-options">
                            <label class="racore-checkbox">
                                <input type="checkbox" name="include_uppercase" checked>
                                <span class="racore-checkmark"></span>
                                Böyük hərflər (A-Z)
                            </label>
                            <label class="racore-checkbox">
                                <input type="checkbox" name="include_lowercase" checked>
                                <span class="racore-checkmark"></span>
                                Kiçik hərflər (a-z)
                            </label>
                            <label class="racore-checkbox">
                                <input type="checkbox" name="include_numbers" checked>
                                <span class="racore-checkmark"></span>
                                Rəqəmlər (0-9)
                            </label>
                            <label class="racore-checkbox">
                                <input type="checkbox" name="include_symbols" checked>
                                <span class="racore-checkmark"></span>
                                Simvollar (!@#$%^&*)
                            </label>
                            <label class="racore-checkbox">
                                <input type="checkbox" name="exclude_similar">
                                <span class="racore-checkmark"></span>
                                Bənzər simvolları istisna et (iIlLoO01)
                            </label>
                        </div>

                        <div class="racore-form-actions">
                            <button type="submit" class="racore-btn racore-btn-primary">
                                <i class="fas fa-magic"></i>
                                Parol Yaradın
                            </button>
                            <button type="button" class="racore-btn racore-btn-secondary" onclick="generatePasswordPreview()">
                                <i class="fas fa-eye"></i>
                                Ön İzləmə
                            </button>
                        </div>

                        <div class="racore-password-preview" id="password-preview" style="display: none;">
                            <strong>Ön İzləmə:</strong>
                            <code id="preview-password"></code>
                        </div>
                    </form>
                </div>
            </div>

            <div class="racore-stats-section">
                <h2 class="racore-stats-title">📊 Sistem Statistikası</h2>
                <div class="racore-stats-grid">
                    <div class="racore-stat-card-large">
                        <i class="fas fa-chart-line"></i>
                        <div class="racore-stat-number"><?php echo $stats['total_requests'] ?? 0; ?></div>
                        <div class="racore-stat-label">Ümumi Sorğular</div>
                    </div>
                    <div class="racore-stat-card-large">
                        <i class="fas fa-fingerprint"></i>
                        <div class="racore-stat-number"><?php echo $stats['hash_requests'] ?? 0; ?></div>
                        <div class="racore-stat-label">Hash Sorğuları</div>
                    </div>
                    <div class="racore-stat-card-large">
                        <i class="fas fa-lock"></i>
                        <div class="racore-stat-number"><?php echo $stats['encrypt_requests'] ?? 0; ?></div>
                        <div class="racore-stat-label">Şifrələmə Sorğuları</div>
                    </div>
                    <div class="racore-stat-card-large">
                        <i class="fas fa-users"></i>
                        <div class="racore-stat-number"><?php echo $stats['unique_users'] ?? 0; ?></div>
                        <div class="racore-stat-label">Unikal İstifadəçilər</div>
                    </div>
                </div>

                <div class="racore-algorithm-stats">
                    <h3>🎯 Alqoritm Statistikası</h3>
                    <div class="racore-algorithm-list">
                        <?php foreach ($stats['algorithm_stats'] ?? [] as $algo => $count): ?>
                        <div class="racore-algorithm-item">
                            <span class="racore-algorithm-name"><?php echo htmlspecialchars($algo); ?></span>
                            <span class="racore-algorithm-count"><?php echo $count; ?> sorğu</span>
                        </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

            <div class="racore-stats">
                <div class="racore-stat-card">
                    <i class="fas fa-bolt"></i>
                    <div class="racore-stat-value" id="processing-time">0ms</div>
                    <div class="racore-stat-label">Emal Müddəti</div>
                </div>
                <div class="racore-stat-card">
                    <i class="fas fa-shield-alt"></i>
                    <div class="racore-stat-value" id="security-level">Yüksək</div>
                    <div class="racore-stat-label">Təhlükəsizlik Səviyyəsi</div>
                </div>
                <div class="racore-stat-card">
                    <i class="fas fa-code-branch"></i>
                    <div class="racore-stat-value">14+</div>
                    <div class="racore-stat-label">Alqoritm</div>
                </div>
            </div>
        </div>
    </main>

    <footer class="racore-footer">
        <div class="racore-container">
            <div class="racore-footer-content">
                <p>&copy; 2024 RACORE Technologies. Bütün hüquqlar qorunur.</p>
                <div class="racore-license">
                    <i class="fas fa-certificate"></i>
                    RACORE MÜXTƏSİR LİSENZİYA v4.1
                </div>
            </div>
        </div>
    </footer>

    <script src="scripts/racore-main.js?v=4.1"></script>
</body>
</html>