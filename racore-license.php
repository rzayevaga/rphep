<?php
class RacoreLicense {
    private static $valid_license;
    private static $required_files;
    
    public static function init() {
        self::$valid_license = 'RACORE-' . md5('secure_hash_platform_2024_prod');
        self::$required_files = array('index.php', 'racore-core.php', 'racore-license.php');
    }
    
    public static function verify() {
        self::init();
        
        if (!defined('RACORE_ROOT')) {
            return false;
        }
        
        if (!defined('RACORE_LICENSE_KEY') || RACORE_LICENSE_KEY !== self::$valid_license) {
            return false;
        }
        
        if (!self::checkFileIntegrity()) {
            return false;
        }
        
        return true;
    }
    
    private static function checkFileIntegrity() {
        foreach (self::$required_files as $file) {
            $file_path = RACORE_ROOT . '/' . $file;
            
            if (!file_exists($file_path)) {
                return false;
            }
            
            if (!is_readable($file_path)) {
                return false;
            }
            
            $content = file_get_contents($file_path);
            if ($content === false) {
                return false;
            }
            
            if (strpos($content, 'RACORE') === false) {
                return false;
            }
        }
        return true;
    }
    
    public static function generateLicenseHash($data) {
        return 'RACORE-' . md5($data . '2024_secure_platform_prod');
    }
}

RacoreLicense::init();
?>