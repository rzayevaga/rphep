<?php
class RacoreCore {
    private $start_time;
    private $csrf_tokens;
    
    public function __construct() {
        $this->start_time = microtime(true);
        $this->csrf_tokens = array();
        $this->initSecurity();
    }
    
    private function initSecurity() {
        if (session_status() === PHP_SESSION_NONE) {
            ini_set('session.cookie_httponly', 1);
            ini_set('session.use_strict_mode', 1);
            ini_set('session.cookie_secure', 1);
            ini_set('session.cookie_samesite', 'Strict');
            session_start();
        }
        
        if (!isset($_SESSION['racore_stats'])) {
            $_SESSION['racore_stats'] = [
                'total_requests' => 0,
                'hash_requests' => 0,
                'encrypt_requests' => 0,
                'verify_requests' => 0,
                'keygen_requests' => 0,
                'passwordgen_requests' => 0,
                'unique_users' => [],
                'algorithm_stats' => []
            ];
        }
        
        $user_ip = $this->getClientIP();
        if (!in_array($user_ip, $_SESSION['racore_stats']['unique_users'])) {
            $_SESSION['racore_stats']['unique_users'][] = $user_ip;
        }
        
        if (!headers_sent()) {
            header('X-Frame-Options: DENY');
            header('X-Content-Type-Options: nosniff');
            header('X-XSS-Protection: 1; mode=block');
            header('Referrer-Policy: strict-origin-when-cross-origin');
            header('X-Permitted-Cross-Domain-Policies: none');
        }
        
        if (!isset($_SESSION['racore_csrf_tokens'])) {
            $_SESSION['racore_csrf_tokens'] = array();
        }
        $this->csrf_tokens = &$_SESSION['racore_csrf_tokens'];
        $this->cleanOldCSRFTokens();
    }
    
    public function generateCSRFToken() {
        $token = bin2hex(random_bytes(32));
        $this->csrf_tokens[$token] = time();
        return $token;
    }
    
    private function validateCSRFToken($token) {
        if (isset($this->csrf_tokens[$token])) {
            $token_time = $this->csrf_tokens[$token];
            if (time() - $token_time < 3600) {
                unset($this->csrf_tokens[$token]);
                return true;
            }
        }
        return false;
    }
    
    private function cleanOldCSRFTokens() {
        foreach ($this->csrf_tokens as $token => $timestamp) {
            if (time() - $timestamp > 3600) {
                unset($this->csrf_tokens[$token]);
            }
        }
    }
    
    public function checkRateLimit() {
        $client_ip = $this->getClientIP();
        $key = 'ratelimit_' . md5($client_ip);
        
        if (!isset($_SESSION[$key])) {
            $_SESSION[$key] = array('count' => 0, 'time' => time());
        }
        
        $rate_data = &$_SESSION[$key];
        
        if (time() - $rate_data['time'] > 60) {
            $rate_data = array('count' => 0, 'time' => time());
        }
        
        if ($rate_data['count'] >= 30) {
            return false;
        }
        
        $rate_data['count']++;
        return true;
    }
    
    private function getClientIP() {
        $ip_keys = array('HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR');
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = trim(explode(',', $_SERVER[$key])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '0.0.0.0';
    }
    
    public function processRequest($data) {
        $_SESSION['racore_stats']['total_requests']++;
        
        if (!isset($data['csrf_token']) || !$this->validateCSRFToken($data['csrf_token'])) {
            throw new Exception('Təhlükəsizlik tokeni yanlış və ya müddəti bitmiş');
        }
        
        $action = isset($data['action']) ? $data['action'] : '';
        $result = array();
        $data = $this->sanitizeInput($data);
        
        try {
            switch ($action) {
                case 'hash':
                    $_SESSION['racore_stats']['hash_requests']++;
                    $result = $this->processHash($data);
                    break;
                    
                case 'encrypt':
                    $_SESSION['racore_stats']['encrypt_requests']++;
                    $result = $this->processEncryption($data);
                    break;
                    
                case 'verify':
                    $_SESSION['racore_stats']['verify_requests']++;
                    $result = $this->processVerify($data);
                    break;
                    
                case 'keygen':
                    $_SESSION['racore_stats']['keygen_requests']++;
                    $result = $this->processKeygen($data);
                    break;
                    
                case 'passwordgen':
                    $_SESSION['racore_stats']['passwordgen_requests']++;
                    $result = $this->processPasswordGen($data);
                    break;
                    
                default:
                    throw new Exception('Yanlış əməliyyat');
            }
            
            $result['status'] = 'success';
        } catch (Exception $e) {
            $result = array(
                'status' => 'error',
                'message' => $e->getMessage()
            );
        }
        
        $result['processing_time'] = round((microtime(true) - $this->start_time) * 1000, 2);
        return $result;
    }
    
    public function getStatistics() {
        $stats = $_SESSION['racore_stats'];
        $stats['unique_users_count'] = count($stats['unique_users']);
        
        $default_algorithms = [
            'BCRYPT' => 0,
            'ARGON2I' => 0,
            'ARGON2ID' => 0,
            'SHA256' => 0,
            'SHA512' => 0,
            'SHA3-256' => 0,
            'SHA3-512' => 0,
            'WHIRLPOOL' => 0,
            'AES-256-CBC' => 0,
            'AES-128-CBC' => 0,
            'AES-256-GCM' => 0,
            'AES-128-GCM' => 0,
            'CHACHA20-POLY1305' => 0,
            'BLOWFISH' => 0
        ];
        
        $stats['algorithm_stats'] = array_merge($default_algorithms, $stats['algorithm_stats'] ?? []);
        
        return [
            'total_requests' => $stats['total_requests'],
            'hash_requests' => $stats['hash_requests'],
            'encrypt_requests' => $stats['encrypt_requests'],
            'verify_requests' => $stats['verify_requests'],
            'keygen_requests' => $stats['keygen_requests'],
            'passwordgen_requests' => $stats['passwordgen_requests'],
            'unique_users' => $stats['unique_users_count'],
            'algorithm_stats' => $stats['algorithm_stats']
        ];
    }
    
    private function sanitizeInput($data) {
        foreach ($data as $key => $value) {
            if (is_string($value)) {
                $value = str_replace(chr(0), '', $value);
                $value = trim($value);
                $data[$key] = $value;
            }
        }
        return $data;
    }
    
    private function processHash($data) {
        $password = isset($data['password']) ? $data['password'] : '';
        $algorithm = isset($data['algorithm']) ? $data['algorithm'] : 'bcrypt';
        $cost = isset($data['cost']) ? intval($data['cost']) : 12;
        
        if (empty($password)) {
            throw new Exception('Şifrə tələb olunur');
        }
        
        if (strlen($password) > 255) {
            throw new Exception('Şifrə çox uzundur');
        }
        
        if ($cost < 4 || $cost > 31) {
            throw new Exception('Yanlış cost parametri');
        }
        
        $hash = '';
        $options = array();
        
        $algo_key = strtoupper($algorithm);
        if (!isset($_SESSION['racore_stats']['algorithm_stats'][$algo_key])) {
            $_SESSION['racore_stats']['algorithm_stats'][$algo_key] = 0;
        }
        $_SESSION['racore_stats']['algorithm_stats'][$algo_key]++;
        
        switch ($algorithm) {
            case 'bcrypt':
                $options = array('cost' => max(4, min(31, $cost)));
                $hash = password_hash($password, PASSWORD_BCRYPT, $options);
                break;
                
            case 'argon2i':
                if (!defined('PASSWORD_ARGON2I')) {
                    throw new Exception('ARGON2I bu serverdə dəstəklənmir');
                }
                $options = array(
                    'memory_cost' => 1 << 17,
                    'time_cost'   => 4,
                    'threads'     => 3
                );
                $hash = password_hash($password, PASSWORD_ARGON2I, $options);
                break;
                
            case 'argon2id':
                if (!defined('PASSWORD_ARGON2ID')) {
                    throw new Exception('ARGON2ID bu serverdə dəstəklənmir');
                }
                $options = array(
                    'memory_cost' => 1 << 17,
                    'time_cost'   => 4,
                    'threads'     => 3
                );
                $hash = password_hash($password, PASSWORD_ARGON2ID, $options);
                break;
                
            case 'sha256':
                $hash = hash('sha256', $password);
                break;
                
            case 'sha512':
                $hash = hash('sha512', $password);
                break;
                
            case 'sha3-256':
                if (in_array('sha3-256', hash_algos())) {
                    $hash = hash('sha3-256', $password);
                } else {
                    throw new Exception('SHA3-256 bu serverdə dəstəklənmir');
                }
                break;
                
            case 'sha3-512':
                if (in_array('sha3-512', hash_algos())) {
                    $hash = hash('sha3-512', $password);
                } else {
                    throw new Exception('SHA3-512 bu serverdə dəstəklənmir');
                }
                break;
                
            case 'whirlpool':
                if (in_array('whirlpool', hash_algos())) {
                    $hash = hash('whirlpool', $password);
                } else {
                    throw new Exception('Whirlpool bu serverdə dəstəklənmir');
                }
                break;
                
            default:
                throw new Exception('Dəstəklənməyən alqoritm');
        }
        
        if (!$hash) {
            throw new Exception('Hash yaradılması uğursuz oldu');
        }
        
        return array(
            'message' => $algorithm . " alqoritmi uğurla istifadə edildi",
            'hash' => $hash,
            'details' => "Seçimlər: " . json_encode($options, JSON_PRETTY_PRINT)
        );
    }
    
    private function processEncryption($data) {
        $text = isset($data['data']) ? $data['data'] : '';
        $key = isset($data['encryption_key']) ? $data['encryption_key'] : '';
        $method = isset($data['encryption_method']) ? $data['encryption_method'] : 'aes-256-cbc';
        $operation = isset($data['operation']) ? $data['operation'] : 'encrypt';
        
        if (empty($text) || empty($key)) {
            throw new Exception('Mətn və açar tələb olunur');
        }
        
        if (strlen($text) > 10000) {
            throw new Exception('Mətn çox uzundur');
        }
        
        if (strlen($key) > 255) {
            throw new Exception('Açar çox uzundur');
        }
        
        $algo_key = strtoupper($method);
        if (!isset($_SESSION['racore_stats']['algorithm_stats'][$algo_key])) {
            $_SESSION['racore_stats']['algorithm_stats'][$algo_key] = 0;
        }
        $_SESSION['racore_stats']['algorithm_stats'][$algo_key]++;
        
        $available_methods = openssl_get_cipher_methods();
        if (!in_array($method, $available_methods)) {
            throw new Exception('Dəstəklənməyən şifrələmə metodu: ' . $method);
        }
        
        $iv_length = openssl_cipher_iv_length($method);
        if ($iv_length === false) {
            throw new Exception('IV uzunluğu müəyyən edilə bilmədi');
        }
        
        if ($operation === 'encrypt') {
            $iv = openssl_random_pseudo_bytes($iv_length);
            if ($iv === false) {
                throw new Exception('Təhlükəsiz IV yaradıla bilmədi');
            }
            
            if (strpos($method, 'gcm') !== false) {
                $tag = '';
                $encrypted = openssl_encrypt($text, $method, $key, OPENSSL_RAW_DATA, $iv, $tag);
                if ($encrypted === false) {
                    throw new Exception('Şifrələmə uğursuz oldu');
                }
                $result = base64_encode($iv . $encrypted . $tag);
                $message = "Mətn autentifikasiya teqi ilə uğurla şifrələndi";
            } else {
                $encrypted = openssl_encrypt($text, $method, $key, 0, $iv);
                if ($encrypted === false) {
                    throw new Exception('Şifrələmə uğursuz oldu');
                }
                $result = base64_encode($iv . $encrypted);
                $message = "Mətn uğurla şifrələndi";
            }
            
            $message .= "\nMetod: " . $method . "\nIV uzunluğu: " . $iv_length . " bayt";
        } else {
            $decoded_data = base64_decode($text);
            if ($decoded_data === false) {
                throw new Exception('Base64 dekodlaşdırma uğursuz oldu');
            }
            
            if (strlen($decoded_data) < $iv_length) {
                throw new Exception('Şifrəli mətn çox qısadır');
            }
            
            $iv = substr($decoded_data, 0, $iv_length);
            
            if (strpos($method, 'gcm') !== false) {
                $tag_length = 16;
                $encrypted = substr($decoded_data, $iv_length, -$tag_length);
                $tag = substr($decoded_data, -$tag_length);
                $decrypted = openssl_decrypt($encrypted, $method, $key, OPENSSL_RAW_DATA, $iv, $tag);
            } else {
                $encrypted = substr($decoded_data, $iv_length);
                $decrypted = openssl_decrypt($encrypted, $method, $key, 0, $iv);
            }
            
            if ($decrypted === false) {
                throw new Exception('Deşifrələmə uğursuz oldu - yanlış açar və ya zədələnmiş məlumat');
            }
            
            $result = $decrypted;
            $message = "Mətn uğurla deşifrələndi\nMetod: " . $method;
        }
        
        return array(
            'message' => $message,
            'hash' => $result
        );
    }
    
    private function processVerify($data) {
        $password = isset($data['verify_password']) ? $data['verify_password'] : '';
        $hash = isset($data['verify_hash']) ? $data['verify_hash'] : '';
        
        if (empty($password) || empty($hash)) {
            throw new Exception('Şifrə və hash tələb olunur');
        }
        
        if (password_verify($password, $hash)) {
            $info = password_get_info($hash);
            return array(
                'message' => "✅ Hash şifrə ilə uyğun gəlir!",
                'hash' => 'TƏSDİQLƏNDİ',
                'details' => "Alqoritm: " . $this->getAlgorithmName($info['algo']) . "\nSeçimlər: " . json_encode($info['options'], JSON_PRETTY_PRINT)
            );
        }
        
        $algorithms = array('sha256', 'sha512', 'sha3-256', 'sha3-512', 'whirlpool');
        foreach ($algorithms as $algo) {
            if (in_array($algo, hash_algos())) {
                $computed = hash($algo, $password);
                if (hash_equals($computed, $hash)) {
                    return array(
                        'message' => "✅ Hash şifrə ilə uyğun gəlir!",
                        'hash' => 'TƏSDİQLƏNDİ',
                        'details' => "Alqoritm: " . strtoupper($algo)
                    );
                }
            }
        }
        
        throw new Exception('❌ Hash şifrə ilə uyğun gəlmir');
    }
    
    private function processKeygen($data) {
        $length = isset($data['key_length']) ? intval($data['key_length']) : 32;
        $format = isset($data['key_format']) ? $data['key_format'] : 'hex';
        
        if ($length < 16 || $length > 64) {
            throw new Exception('Açar uzunluğu 16 ilə 64 bayt arasında olmalıdır');
        }
        
        $key = random_bytes($length);
        
        switch ($format) {
            case 'hex':
                $result = bin2hex($key);
                break;
            case 'base64':
                $result = base64_encode($key);
                break;
            case 'base64url':
                $result = str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($key));
                break;
            default:
                throw new Exception('Dəstəklənməyən format');
        }
        
        return array(
            'message' => "Təhlükəsiz təsadüfi açar uğurla yaradıldı",
            'hash' => $result,
            'details' => "Uzunluq: " . $length . " bayt\nFormat: " . strtoupper($format)
        );
    }
    
    private function processPasswordGen($data) {
        $length = isset($data['password_length']) ? intval($data['password_length']) : 16;
        $include_uppercase = isset($data['include_uppercase']);
        $include_lowercase = isset($data['include_lowercase']);
        $include_numbers = isset($data['include_numbers']);
        $include_symbols = isset($data['include_symbols']);
        $exclude_similar = isset($data['exclude_similar']);
        
        if ($length < 8 || $length > 64) {
            throw new Exception('Parol uzunluğu 8 ilə 64 simvol arasında olmalıdır');
        }
        
        if (!$include_uppercase && !$include_lowercase && !$include_numbers && !$include_symbols) {
            throw new Exception('Ən azı bir simvol növü seçilməlidir');
        }
        
        $uppercase = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        $lowercase = 'abcdefghjkmnpqrstuvwxyz';
        $numbers = '23456789';
        $symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        
        if (!$exclude_similar) {
            $uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
            $lowercase = 'abcdefghijklmnopqrstuvwxyz';
            $numbers = '0123456789';
        }
        
        $characters = '';
        if ($include_uppercase) $characters .= $uppercase;
        if ($include_lowercase) $characters .= $lowercase;
        if ($include_numbers) $characters .= $numbers;
        if ($include_symbols) $characters .= $symbols;
        
        if (empty($characters)) {
            throw new Exception('Parol yaratmaq üçün simvol yoxdur');
        }
        
        $password = '';
        $characters_length = strlen($characters);
        
        for ($i = 0; $i < $length; $i++) {
            $password .= $characters[random_int(0, $characters_length - 1)];
        }
        
        $required_chars = [];
        if ($include_uppercase) {
            $required_chars[] = $uppercase[random_int(0, strlen($uppercase) - 1)];
        }
        if ($include_lowercase) {
            $required_chars[] = $lowercase[random_int(0, strlen($lowercase) - 1)];
        }
        if ($include_numbers) {
            $required_chars[] = $numbers[random_int(0, strlen($numbers) - 1)];
        }
        if ($include_symbols) {
            $required_chars[] = $symbols[random_int(0, strlen($symbols) - 1)];
        }
        
        foreach ($required_chars as $char) {
            $pos = random_int(0, $length - 1);
            $password = substr_replace($password, $char, $pos, 1);
        }
        
        $details = "Uzunluq: " . $length . " simvol\n";
        $details .= "Simvol dəstləri: ";
        $sets = [];
        if ($include_uppercase) $sets[] = "Böyük hərflər";
        if ($include_lowercase) $sets[] = "Kiçik hərflər";
        if ($include_numbers) $sets[] = "Rəqəmlər";
        if ($include_symbols) $sets[] = "Simvollar";
        $details .= implode(", ", $sets);
        
        if ($exclude_similar) {
            $details .= "\nBənzər simvollar istisna edildi";
        }
        
        return array(
            'message' => "Güclü parol uğurla yaradıldı",
            'hash' => $password,
            'details' => $details
        );
    }
    
    private function getAlgorithmName($algo) {
        $names = array(
            PASSWORD_BCRYPT => 'BCRYPT',
            PASSWORD_ARGON2I => 'ARGON2I',
            PASSWORD_ARGON2ID => 'ARGON2ID'
        );
        
        return isset($names[$algo]) ? $names[$algo] : 'BƏLİRSİZ';
    }
    
    public function getProcessingTime() {
        return round((microtime(true) - $this->start_time) * 1000, 2);
    }
}
?>