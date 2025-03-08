/**
 * Plugin Name: Lunar Login Shield
 * Description: Plugin keamanan login dengan fitur auto ban IP & Fingerprint, honeypot untuk mencegah bot, log aktivitas login, dan notifikasi WhatsApp.
 * Version: 1.7
 * Author: Novian Bayu Putranto
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

class Lunar_Login_Shield {
    private $max_attempts = 3;
    private $ban_duration = 600; // 10 menit
    private $api_key = 'xxxxxxxxxxxxxxxx';
    private $sender = '62xxxxxxxxxxx';
    private $admin_number = '62xxxxxxx';

    public function __construct() {
        register_activation_hook(__FILE__, [$this, 'create_database_table']);
        add_action('admin_menu', [$this, 'add_admin_page']);
        add_action('wp_login_failed', [$this, 'track_failed_login']);
        add_filter('authenticate', [$this, 'check_login_attempts'], 30, 3);
        add_action('wp_login', [$this, 'track_successful_login'], 10, 2);
        add_action('clear_auth_cookie', [$this, 'track_logout']);
        add_action('login_form', [$this, 'add_honeypot_field']);
        add_action('wp_authenticate', [$this, 'check_honeypot_field']);
    }

    public function create_database_table() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'lunar_login_shield_logs';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS $table_name (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            ip_address VARCHAR(100) NOT NULL,
            fingerprint VARCHAR(255) NOT NULL,
            login_time DATETIME NOT NULL,
            logout_time DATETIME NULL,
            status VARCHAR(20) NOT NULL
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    public function add_admin_page() {
        add_menu_page('Lunar Login Shield Logs', 'Lunar Login Shield', 'manage_options', 'lunar-login-shield-logs', [$this, 'display_logs'], 'dashicons-shield', 75);
    }

    public function display_logs() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'lunar_login_shield_logs';
        $logs = $wpdb->get_results("SELECT * FROM $table_name ORDER BY login_time DESC LIMIT 50");

        echo '<div class="wrap"><h1>Lunar Login Shield Logs</h1><table class="wp-list-table widefat fixed striped">';
        echo '<thead><tr><th>User ID</th><th>IP Address</th><th>Fingerprint</th><th>Login Time</th><th>Logout Time</th><th>Status</th></tr></thead><tbody>';
        foreach ($logs as $log) {
            echo "<tr><td>{$log->user_id}</td><td>{$log->ip_address}</td><td>{$log->fingerprint}</td><td>{$log->login_time}</td><td>{$log->logout_time}</td><td>{$log->status}</td></tr>";
        }
        echo '</tbody></table></div>';
    }

    public function track_failed_login($username) {
        global $wpdb;
        $ip = $this->get_user_ip();
        $fingerprint = $this->get_device_fingerprint();

        $attempts = get_transient("login_attempts_$fingerprint") ?: 0;
        $attempts++;
        set_transient("login_attempts_$fingerprint", $attempts, $this->ban_duration);

        if ($attempts >= $this->max_attempts) {
            set_transient("banned_fingerprint_$fingerprint", true, $this->ban_duration);
            $this->send_whatsapp_alert($ip, $fingerprint);
        }

        $wpdb->insert($wpdb->prefix . 'lunar_login_shield_logs', [
            'user_id' => 0,
            'ip_address' => $ip,
            'fingerprint' => $fingerprint,
            'login_time' => current_time('mysql'),
            'logout_time' => NULL,
            'status' => 'Failed'
        ]);
    }

    public function check_login_attempts($user, $username, $password) {
        $fingerprint = $this->get_device_fingerprint();
        if (get_transient("banned_fingerprint_$fingerprint")) {
            return new WP_Error('too_many_attempts', __('Too many failed login attempts. Try again later.'));
        }
        return $user;
    }

    public function track_successful_login($user_login, $user) {
        global $wpdb;
        $ip = $this->get_user_ip();
        $fingerprint = $this->get_device_fingerprint();

        delete_transient("login_attempts_$fingerprint");

        $wpdb->insert($wpdb->prefix . 'lunar_login_shield_logs', [
            'user_id' => $user->ID,
            'ip_address' => $ip,
            'fingerprint' => $fingerprint,
            'login_time' => current_time('mysql'),
            'logout_time' => NULL,
            'status' => 'Success'
        ]);
    }

    public function track_logout() {
        $user_id = get_current_user_id();
        if ($user_id) {
            global $wpdb;
            $table_name = $wpdb->prefix . 'lunar_login_shield_logs';
            $wpdb->query($wpdb->prepare(
                "UPDATE $table_name SET logout_time = NOW() WHERE user_id = %d AND logout_time IS NULL ORDER BY login_time DESC LIMIT 1",
                $user_id
            ));
        }
    }

    public function add_honeypot_field() {
        echo '<input type="text" name="honeypot_field" value="" style="display:none;">';
    }

    public function check_honeypot_field($username) {
        if (!empty($_POST['honeypot_field'])) {
            wp_die(__('Error: Suspicious activity detected.'));
        }
    }

    private function get_user_ip() {
        return $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    }

    private function get_device_fingerprint() {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $ip = $this->get_user_ip();
        return md5($user_agent . $ip);
    }

    private function send_whatsapp_alert($ip, $fingerprint) {
        $message = "[ALERT] 🚨 Percobaan login gagal 3x! IP: $ip\nFingerprint: $fingerprint\n📅 Waktu: " . current_time('mysql') . "\n🔒 Perangkat telah diblokir sementara.";
        $this->send_whatsapp_message($message);
    }

    private function send_whatsapp_message($message) {
        $api_url = "https://sender.digilunar.com/send-message?api_key={$this->api_key}&sender={$this->sender}&number={$this->admin_number}&message=" . urlencode($message);
        wp_remote_get($api_url, ['method' => 'POST']);
    }
}

new Lunar_Login_Shield();
