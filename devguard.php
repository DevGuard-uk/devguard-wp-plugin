<?php
/**
 * Plugin Name: DevGuard
 * Plugin URI: https://github.com/DevGuard-uk/devguard-wp-plugin
 * Description: Protect client websites with remote project locking, invoice milestone autolock enforcement, and domain allowlisting.
 * Version: 1.0.0
 * Author: DevGuard Security
 * Author URI: https://devguard.uk
 * License: MIT
 * Text Domain: devguard
 */

if (!defined('ABSPATH')) {
    exit;
}

// 1. Autoload DevGuard PHP Guard classes
if (!class_exists('DevGuard\\WebGuard')) {
    $baseDir = __DIR__ . '/includes';

    if (file_exists($baseDir . '/DomainMatcher.php')) {
        require_once $baseDir . '/DomainMatcher.php';
    }
    if (file_exists($baseDir . '/LockResponse.php')) {
        require_once $baseDir . '/LockResponse.php';
    }
    if (file_exists($baseDir . '/Cache.php')) {
        require_once $baseDir . '/Cache.php';
    }
    if (file_exists($baseDir . '/WebGuard.php')) {
        require_once $baseDir . '/WebGuard.php';
    }
}

/**
 * Main DevGuard WordPress Plugin Class
 */
class DevGuard_WordPress_Plugin
{
    private static ?DevGuard_WordPress_Plugin $instance = null;
    private ?\DevGuard\WebGuard $guard = null;
    private ?array $lastCheck = null;

    public static function instance(): DevGuard_WordPress_Plugin
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct()
    {
        add_action('init', [$this, 'initGuard']);
        add_action('template_redirect', [$this, 'enforceFrontendLock'], 1);
        add_action('admin_menu', [$this, 'registerAdminMenu']);
        add_action('admin_init', [$this, 'registerSettings']);
        add_action('admin_notices', [$this, 'renderAdminBypassNotice']);
        add_action('wp_footer', [$this, 'renderFrontendAdminBarNotice']);

        register_activation_hook(__FILE__, [$this, 'onActivation']);
        register_deactivation_hook(__FILE__, [$this, 'onDeactivation']);
    }

    public function onActivation(): void
    {
        if (get_option('devguard_api_url') === false) {
            update_option('devguard_api_url', 'https://api.devguard.uk');
        }
        if (get_option('devguard_cache_ttl') === false) {
            update_option('devguard_cache_ttl', 60);
        }
        if (get_option('devguard_fail_safe') === false) {
            update_option('devguard_fail_safe', 'open');
        }
    }

    public function onDeactivation(): void
    {
        $projectId = $this->getProjectId();
        if ($projectId !== '') {
            delete_transient('devguard_status_' . $projectId);
        }
    }

    public function getProjectId(): string
    {
        if (defined('DEVGUARD_PROJECT_ID') && constant('DEVGUARD_PROJECT_ID')) {
            return trim((string)constant('DEVGUARD_PROJECT_ID'));
        }
        return trim((string)get_option('devguard_project_id', ''));
    }

    public function getApiUrl(): string
    {
        if (defined('DEVGUARD_API_URL') && constant('DEVGUARD_API_URL')) {
            return rtrim((string)constant('DEVGUARD_API_URL'), '/');
        }
        return rtrim((string)get_option('devguard_api_url', 'https://api.devguard.uk'), '/');
    }

    public function getApiKey(): ?string
    {
        if (defined('DEVGUARD_API_KEY') && constant('DEVGUARD_API_KEY')) {
            return (string)constant('DEVGUARD_API_KEY');
        }
        $key = (string)get_option('devguard_api_key', '');
        return $key !== '' ? $key : null;
    }

    public function getCacheTtl(): int
    {
        if (defined('DEVGUARD_CACHE_TTL')) {
            return max(5, (int)constant('DEVGUARD_CACHE_TTL'));
        }
        return max(5, (int)get_option('devguard_cache_ttl', 60));
    }

    public function getFailSafe(): string
    {
        if (defined('DEVGUARD_FAIL_SAFE')) {
            return constant('DEVGUARD_FAIL_SAFE') === 'closed' ? 'closed' : 'open';
        }
        return get_option('devguard_fail_safe', 'open') === 'closed' ? 'closed' : 'open';
    }

    public function getAllowedDomains(): ?string
    {
        if (defined('DEVGUARD_ALLOWED_DOMAINS')) {
            return (string)constant('DEVGUARD_ALLOWED_DOMAINS');
        }
        $domains = (string)get_option('devguard_allowed_domains', '');
        return $domains !== '' ? $domains : null;
    }

    /**
     * Initializes DevGuard WebGuard instance.
     */
    public function initGuard(): void
    {
        $projectId = $this->getProjectId();
        if ($projectId === '') {
            return;
        }

        if (!class_exists('DevGuard\\WebGuard')) {
            return;
        }

        // Custom WordPress Transient Cache adapter
        $wpCacheAdapter = [
            'get' => function (string $key): ?array {
                $cached = get_transient($key);
                if ($cached !== false && is_array($cached)) {
                    return [
                        'data' => $cached,
                        'isFresh' => true,
                    ];
                }
                return null;
            },
            'set' => function (string $key, $data, int $ttl): void {
                set_transient($key, $data, $ttl);
            },
            'clear' => function (?string $key = null): void {
                if ($key !== null) {
                    delete_transient($key);
                }
            },
        ];

        $config = [
            'projectId' => $projectId,
            'apiUrl' => $this->getApiUrl(),
            'apiKey' => $this->getApiKey(),
            'failSafe' => $this->getFailSafe(),
            'cacheTtl' => $this->getCacheTtl(),
            'allowedDomains' => $this->getAllowedDomains(),
            'cache' => new class($wpCacheAdapter) {
                private array $adapter;
                public function __construct(array $adapter) { $this->adapter = $adapter; }
                public function get(string $key): ?array { return ($this->adapter['get'])($key); }
                public function set(string $key, $data, int $ttl): void { ($this->adapter['set'])($key, $data, $ttl); }
                public function clear(?string $key = null): void { ($this->adapter['clear'])($key); }
            },
            'allowedPaths' => [
                '/wp-login.php',
                '/wp-cron.php',
                '/xmlrpc.php',
            ],
        ];

        $this->guard = new \DevGuard\WebGuard($config);
    }

    /**
     * Enforces frontend locking while granting bypass access to logged-in WordPress administrators.
     */
    public function enforceFrontendLock(): void
    {
        if ($this->guard === null) {
            return;
        }

        // Always bypass admin backend, cron, and login page
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        if (is_admin() || wp_doing_cron() || strpos($uri, 'wp-login.php') !== false) {
            return;
        }

        // Check status
        $this->lastCheck = $this->guard->check();

        // Admin Bypass Guarantee: Logged-in administrators are NEVER locked out
        if (is_user_logged_in() && current_user_can('manage_options')) {
            return;
        }

        // Non-admin visitors: enforce lock
        if (empty($this->lastCheck['allowed'])) {
            $isJson = \DevGuard\LockResponse::isApiRequest($_SERVER);
            \DevGuard\LockResponse::sendLockResponse($this->lastCheck, $isJson, true);
        }
    }

    /**
     * Renders admin bypass notice in wp-admin if project is currently locked to the public.
     */
    public function renderAdminBypassNotice(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $check = $this->getCurrentStatusCheck();
        if ($check === null || !empty($check['allowed'])) {
            return;
        }

        $projectId = esc_html($this->getProjectId());
        $title = esc_html($check['title'] ?? 'Service Locked');
        $reason = esc_html($check['reason'] ?? 'locked');
        $code = esc_html($check['code'] ?? 'DEVGUARD_LOCKED');
        ?>
        <div class="notice notice-error" style="border-left-color: #ef4444; background: #fff5f5; padding: 12px 16px; margin: 15px 0;">
            <h3 style="margin: 0 0 6px 0; color: #b91c1c; font-size: 14px; font-weight: 700;">
                ⚠️ DevGuard Alert: Website is LOCKED to Public Visitors
            </h3>
            <p style="margin: 0 0 6px 0; color: #4b5563; font-size: 13px;">
                <strong>Project:</strong> <?php echo $projectId; ?> &nbsp;|&nbsp; 
                <strong>Code:</strong> <code><?php echo $code; ?></code> &nbsp;|&nbsp; 
                <strong>Reason:</strong> <?php echo $reason; ?> &nbsp;|&nbsp;
                <strong>Status:</strong> <?php echo $title; ?>
            </p>
            <p style="margin: 0; color: #1e3a8a; font-size: 12px;">
                <em>Administrator Bypass Active: You can navigate and manage WordPress normally. Public visitors currently see an SEO-safe HTTP 503 lock screen.</em>
            </p>
        </div>
        <?php
    }

    /**
     * Renders warning banner in frontend for logged-in administrators when site is locked.
     */
    public function renderFrontendAdminBarNotice(): void
    {
        if (!is_user_logged_in() || !current_user_can('manage_options')) {
            return;
        }

        $check = $this->getCurrentStatusCheck();
        if ($check === null || !empty($check['allowed'])) {
            return;
        }

        $projectId = esc_html($this->getProjectId());
        $reason = esc_html($check['reason'] ?? 'locked');
        ?>
        <div id="devguard-admin-bypass-bar" style="position: fixed; bottom: 0; left: 0; right: 0; z-index: 999999; background: #991b1b; color: #ffffff; padding: 10px 18px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; font-size: 13px; font-weight: 600; box-shadow: 0 -4px 12px rgba(0,0,0,0.3); display: flex; align-items: center; justify-content: space-between;">
            <div>
                ⚠️ <strong>DevGuard Admin Bypass:</strong> This website is currently <u>LOCKED</u> to the public (<?php echo $projectId; ?> &bull; <?php echo $reason; ?>). You have administrator bypass access.
            </div>
            <a href="<?php echo esc_url(admin_url('options-general.php?page=devguard-settings')); ?>" style="color: #ffffff; background: rgba(255,255,255,0.2); padding: 4px 10px; border-radius: 4px; text-decoration: none; font-size: 12px;">Settings</a>
        </div>
        <?php
    }

    public function getCurrentStatusCheck(): ?array
    {
        if ($this->lastCheck !== null) {
            return $this->lastCheck;
        }
        if ($this->guard !== null) {
            $this->lastCheck = $this->guard->check();
            return $this->lastCheck;
        }
        return null;
    }

    public function registerAdminMenu(): void
    {
        add_options_page(
            'DevGuard Settings',
            'DevGuard',
            'manage_options',
            'devguard-settings',
            [$this, 'renderSettingsPage']
        );
    }

    public function registerSettings(): void
    {
        register_setting('devguard_options_group', 'devguard_project_id', ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('devguard_options_group', 'devguard_api_url', ['sanitize_callback' => 'esc_url_raw']);
        register_setting('devguard_options_group', 'devguard_api_key', ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('devguard_options_group', 'devguard_cache_ttl', ['sanitize_callback' => 'absint']);
        register_setting('devguard_options_group', 'devguard_fail_safe', ['sanitize_callback' => 'sanitize_text_field']);
        register_setting('devguard_options_group', 'devguard_allowed_domains', ['sanitize_callback' => 'sanitize_text_field']);
    }

    public function renderSettingsPage(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $projectId = $this->getProjectId();
        $apiUrl = $this->getApiUrl();
        $apiKey = $this->getApiKey() ?? '';
        $cacheTtl = $this->getCacheTtl();
        $failSafe = $this->getFailSafe();
        $allowedDomains = $this->getAllowedDomains() ?? '';

        $isProjectIdConstant = defined('DEVGUARD_PROJECT_ID');
        $isApiUrlConstant = defined('DEVGUARD_API_URL');

        $statusBadge = '<span style="color:#6b7280;">Not configured</span>';
        if ($projectId !== '') {
            $check = $this->getCurrentStatusCheck();
            if ($check !== null) {
                if (!empty($check['allowed'])) {
                    $statusBadge = '<span style="color:#10b981; font-weight:600;">● Active (Public Access Granted)</span>';
                } else {
                    $reason = esc_html($check['reason'] ?? 'locked');
                    $statusBadge = '<span style="color:#ef4444; font-weight:600;">● Locked to Public (' . $reason . ')</span>';
                }
            }
        }
        ?>
        <div class="wrap">
            <h1>DevGuard Protection Settings</h1>
            <p>Connect your WordPress website to DevGuard for automated client project locking, invoice milestone protection, and domain allowlisting.</p>

            <div style="background: #ffffff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; max-width: 720px;">
                <h3 style="margin-top: 0;">Connection Status</h3>
                <p>Status: <?php echo wp_kses_post($statusBadge); ?></p>
            </div>

            <form method="post" action="options.php" style="max-width: 720px;">
                <?php settings_fields('devguard_options_group'); ?>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="devguard_project_id">Project ID</label></th>
                        <td>
                            <input name="devguard_project_id" type="text" id="devguard_project_id" value="<?php echo esc_attr($projectId); ?>" class="regular-text" <?php echo $isProjectIdConstant ? 'readonly' : ''; ?> />
                            <?php if ($isProjectIdConstant): ?>
                                <p class="description">Defined via <code>DEVGUARD_PROJECT_ID</code> constant in <code>wp-config.php</code>.</p>
                            <?php else: ?>
                                <p class="description">Your DevGuard project identifier (from the DevGuard Portal).</p>
                            <?php endif; ?>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="devguard_api_url">API Base URL</label></th>
                        <td>
                            <input name="devguard_api_url" type="url" id="devguard_api_url" value="<?php echo esc_attr($apiUrl); ?>" class="regular-text" <?php echo $isApiUrlConstant ? 'readonly' : ''; ?> />
                            <p class="description">DevGuard backend API (defaults to <code>https://api.devguard.uk</code>).</p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="devguard_api_key">API Key (Optional)</label></th>
                        <td>
                            <input name="devguard_api_key" type="password" id="devguard_api_key" value="<?php echo esc_attr($apiKey); ?>" class="regular-text" />
                            <p class="description">Only required if status checking requires server-to-server API authentication.</p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="devguard_cache_ttl">Cache TTL (Seconds)</label></th>
                        <td>
                            <input name="devguard_cache_ttl" type="number" id="devguard_cache_ttl" value="<?php echo esc_attr($cacheTtl); ?>" min="5" max="86400" class="small-text" />
                            <p class="description">Duration to cache project status in WordPress transients (default 60s).</p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="devguard_fail_safe">Fail-Safe Policy</label></th>
                        <td>
                            <select name="devguard_fail_safe" id="devguard_fail_safe">
                                <option value="open" <?php selected($failSafe, 'open'); ?>>Open (Default - Never block traffic during API outages)</option>
                                <option value="closed" <?php selected($failSafe, 'closed'); ?>>Closed (Strict - Treat unreachable API as locked)</option>
                            </select>
                            <p class="description">Controls behavior if the DevGuard API is unreachable.</p>
                        </td>
                    </tr>

                    <tr>
                        <th scope="row"><label for="devguard_allowed_domains">Allowed Domains Override</label></th>
                        <td>
                            <input name="devguard_allowed_domains" type="text" id="devguard_allowed_domains" value="<?php echo esc_attr($allowedDomains); ?>" class="large-text" placeholder="example.com, *.example.com" />
                            <p class="description">Comma-separated list of allowed domains. Leave blank to inherit from project configuration.</p>
                        </td>
                    </tr>
                </table>

                <?php submit_button('Save DevGuard Settings'); ?>
            </form>
        </div>
        <?php
    }
}

// Instantiate plugin singleton
DevGuard_WordPress_Plugin::instance();
