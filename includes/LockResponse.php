<?php

namespace DevGuard;

/**
 * DevGuard Web Lock Response & Path Allowlist (PHP)
 * Provides SEO-safe HTTP 503 Service Unavailable responses, path bypasses, and JSON lock envelopes.
 */
class LockResponse
{
    public const DEFAULT_ALLOWED_PATHS = [
        '/health',
        '/api/health',
        '/.well-known',
        '/favicon.ico',
        '/robots.txt',
        '/sitemap.xml',
    ];

    /**
     * Checks whether the incoming pathname is exempt from lock enforcement (health checks, well-known certs, etc.)
     *
     * @param string|null $pathname
     * @param array $customAllowedPaths
     * @return bool
     */
    public static function isPathAllowed(?string $pathname, array $customAllowedPaths = []): bool
    {
        if ($pathname === null || $pathname === '') {
            return false;
        }

        $normalized = strpos($pathname, '/') === 0 ? $pathname : '/' . $pathname;

        // Check default bypass paths
        foreach (self::DEFAULT_ALLOWED_PATHS as $def) {
            if ($normalized === $def || strpos($normalized, $def . '/') === 0) {
                return true;
            }
        }

        // Check custom allowed paths
        foreach ($customAllowedPaths as $rule) {
            if (!is_string($rule)) {
                continue;
            }
            // If regex pattern (e.g. #^/api/webhook#)
            if (strlen($rule) > 2 && ($rule[0] === '/' || $rule[0] === '#' || $rule[0] === '~') && substr($rule, -1) === $rule[0]) {
                if (@preg_match($rule, $normalized)) {
                    return true;
                }
            } else {
                $r = strpos($rule, '/') === 0 ? $rule : '/' . $rule;
                if ($normalized === $r || strpos($normalized, $r . '/') === 0) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Produces standard HTTP 503 headers for SEO-safe maintenance.
     *
     * @param int $retryAfter Seconds before client should retry
     * @return array<string, string>
     */
    public static function getLockHeaders(int $retryAfter = 3600): array
    {
        return [
            'Retry-After' => (string)$retryAfter,
            'X-Robots-Tag' => 'noindex, nofollow, noarchive',
            'Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma' => 'no-cache',
            'Expires' => '0',
            'X-DevGuard-Lock' => 'active',
        ];
    }

    /**
     * Escapes HTML entities safely.
     *
     * @param string|null $str
     * @return string
     */
    public static function escapeHtml(?string $str): string
    {
        if ($str === null) {
            return '';
        }
        return htmlspecialchars($str, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    /**
     * Generates an SEO-safe HTML lock page with noindex headers and contact options.
     *
     * @param array $opts
     * @return string Safe HTML document
     */
    public static function generateLockHtml(array $opts = []): string
    {
        $title = self::escapeHtml($opts['title'] ?? 'Service Temporarily Unavailable');
        $message = self::escapeHtml(
            $opts['message'] ??
            'This application is temporarily unavailable due to administrative service suspension. Please contact support or check back later.'
        );
        $appName = self::escapeHtml($opts['appName'] ?? 'DevGuard Protected Application');
        $retryAfter = (int)($opts['retryAfter'] ?? 3600);
        if ($retryAfter <= 0) {
            $retryAfter = 3600;
        }

        $contactLinks = [];
        if (!empty($opts['contactEmail'])) {
            $email = self::escapeHtml($opts['contactEmail']);
            $contactLinks[] = '<a class="dg-btn dg-btn-secondary" href="mailto:' . $email . '">Contact Support (' . $email . ')</a>';
        }
        if (!empty($opts['contactWhatsapp'])) {
            $cleanWa = preg_replace('/[^\d+]/', '', (string)$opts['contactWhatsapp']);
            $wa = self::escapeHtml($cleanWa);
            $contactLinks[] = '<a class="dg-btn dg-btn-secondary" href="https://wa.me/' . $wa . '" target="_blank" rel="noopener">WhatsApp Support</a>';
        }
        if (!empty($opts['contactPhone'])) {
            $phone = self::escapeHtml($opts['contactPhone']);
            $contactLinks[] = '<a class="dg-btn dg-btn-secondary" href="tel:' . $phone . '">Call Support</a>';
        }

        $contactHtml = implode("\n", $contactLinks);

        $html = '<!DOCTYPE html>' . "\n"
            . '<html lang="en">' . "\n"
            . '<head>' . "\n"
            . '  <meta charset="utf-8" />' . "\n"
            . '  <meta name="viewport" content="width=device-width, initial-scale=1" />' . "\n"
            . '  <meta name="robots" content="noindex, nofollow, noarchive" />' . "\n"
            . '  <meta http-equiv="refresh" content="' . $retryAfter . '" />' . "\n"
            . '  <title>' . $title . '</title>' . "\n"
            . '  <style>' . "\n"
            . '    :root {' . "\n"
            . '      --bg: #090d16;' . "\n"
            . '      --card-bg: #111726;' . "\n"
            . '      --border: #1f293d;' . "\n"
            . '      --text-main: #f8fafc;' . "\n"
            . '      --text-muted: #94a3b8;' . "\n"
            . '      --accent: #ef4444;' . "\n"
            . '      --accent-glow: rgba(239, 68, 68, 0.15);' . "\n"
            . '      --btn-bg: #1e293b;' . "\n"
            . '      --btn-hover: #334155;' . "\n"
            . '    }' . "\n"
            . '    * { box-sizing: border-box; margin: 0; padding: 0; }' . "\n"
            . '    body {' . "\n"
            . '      background: radial-gradient(circle at 50% 20%, #151e33 0%, var(--bg) 100%);' . "\n"
            . '      color: var(--text-main);' . "\n"
            . '      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;' . "\n"
            . '      min-height: 100vh;' . "\n"
            . '      display: flex;' . "\n"
            . '      align-items: center;' . "\n"
            . '      justify-content: center;' . "\n"
            . '      padding: 1.5rem;' . "\n"
            . '    }' . "\n"
            . '    .dg-container {' . "\n"
            . '      max-width: 540px;' . "\n"
            . '      width: 100%;' . "\n"
            . '      background: var(--card-bg);' . "\n"
            . '      border: 1px solid var(--border);' . "\n"
            . '      border-radius: 1rem;' . "\n"
            . '      padding: 2.5rem 2rem;' . "\n"
            . '      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.6), 0 0 40px var(--accent-glow);' . "\n"
            . '      text-align: center;' . "\n"
            . '    }' . "\n"
            . '    .dg-badge {' . "\n"
            . '      display: inline-flex;' . "\n"
            . '      align-items: center;' . "\n"
            . '      gap: 0.5rem;' . "\n"
            . '      background: rgba(239, 68, 68, 0.12);' . "\n"
            . '      color: var(--accent);' . "\n"
            . '      border: 1px solid rgba(239, 68, 68, 0.25);' . "\n"
            . '      font-size: 0.75rem;' . "\n"
            . '      font-weight: 600;' . "\n"
            . '      letter-spacing: 0.05em;' . "\n"
            . '      text-transform: uppercase;' . "\n"
            . '      padding: 0.35rem 0.75rem;' . "\n"
            . '      border-radius: 9999px;' . "\n"
            . '      margin-bottom: 1.25rem;' . "\n"
            . '    }' . "\n"
            . '    .dg-badge::before {' . "\n"
            . '      content: "";' . "\n"
            . '      width: 6px;' . "\n"
            . '      height: 6px;' . "\n"
            . '      background: var(--accent);' . "\n"
            . '      border-radius: 50%;' . "\n"
            . '      box-shadow: 0 0 8px var(--accent);' . "\n"
            . '    }' . "\n"
            . '    h1 {' . "\n"
            . '      font-size: 1.5rem;' . "\n"
            . '      font-weight: 700;' . "\n"
            . '      margin-bottom: 0.75rem;' . "\n"
            . '      color: var(--text-main);' . "\n"
            . '      line-height: 1.3;' . "\n"
            . '    }' . "\n"
            . '    .dg-app {' . "\n"
            . '      font-size: 0.875rem;' . "\n"
            . '      color: var(--text-muted);' . "\n"
            . '      margin-bottom: 1.5rem;' . "\n"
            . '    }' . "\n"
            . '    .dg-message {' . "\n"
            . '      font-size: 0.95rem;' . "\n"
            . '      color: #cbd5e1;' . "\n"
            . '      line-height: 1.6;' . "\n"
            . '      margin-bottom: 2rem;' . "\n"
            . '      background: rgba(255, 255, 255, 0.03);' . "\n"
            . '      padding: 1rem 1.25rem;' . "\n"
            . '      border-radius: 0.5rem;' . "\n"
            . '      border: 1px solid rgba(255, 255, 255, 0.06);' . "\n"
            . '    }' . "\n"
            . '    .dg-actions {' . "\n"
            . '      display: flex;' . "\n"
            . '      flex-direction: column;' . "\n"
            . '      gap: 0.75rem;' . "\n"
            . '    }' . "\n"
            . '    .dg-btn {' . "\n"
            . '      display: inline-block;' . "\n"
            . '      width: 100%;' . "\n"
            . '      padding: 0.75rem 1.25rem;' . "\n"
            . '      font-size: 0.875rem;' . "\n"
            . '      font-weight: 600;' . "\n"
            . '      text-decoration: none;' . "\n"
            . '      border-radius: 0.5rem;' . "\n"
            . '      transition: all 0.2s ease;' . "\n"
            . '      cursor: pointer;' . "\n"
            . '    }' . "\n"
            . '    .dg-btn-secondary {' . "\n"
            . '      background: var(--btn-bg);' . "\n"
            . '      color: var(--text-main);' . "\n"
            . '      border: 1px solid var(--border);' . "\n"
            . '    }' . "\n"
            . '    .dg-btn-secondary:hover {' . "\n"
            . '      background: var(--btn-hover);' . "\n"
            . '      border-color: #475569;' . "\n"
            . '    }' . "\n"
            . '    .dg-footer {' . "\n"
            . '      margin-top: 2rem;' . "\n"
            . '      font-size: 0.75rem;' . "\n"
            . '      color: #64748b;' . "\n"
            . '    }' . "\n"
            . '  </style>' . "\n"
            . '</head>' . "\n"
            . '<body>' . "\n"
            . '  <div class="dg-container">' . "\n"
            . '    <div class="dg-badge">HTTP 503 · Service Locked</div>' . "\n"
            . '    <h1>' . $title . '</h1>' . "\n"
            . '    <div class="dg-app">Protected: ' . $appName . '</div>' . "\n"
            . '    <div class="dg-message">' . $message . '</div>' . "\n"
            . '    <div class="dg-actions">' . "\n"
            . '      ' . $contactHtml . "\n"
            . '    </div>' . "\n"
            . '    <div class="dg-footer">' . "\n"
            . '      Secured by DevGuard Protection Framework' . "\n"
            . '    </div>' . "\n"
            . '  </div>' . "\n"
            . '</body>' . "\n"
            . '</html>';

        return $html;
    }

    /**
     * Determines whether the request is an API request expecting JSON.
     *
     * @param array|null $server Defaults to $_SERVER
     * @return bool
     */
    public static function isApiRequest(?array $server = null): bool
    {
        $server = $server ?? $_SERVER;
        $accept = (string)($server['HTTP_ACCEPT'] ?? '');
        $uri = (string)($server['REQUEST_URI'] ?? '');

        if (strpos($accept, 'application/json') !== false) {
            return true;
        }

        if (strpos($uri, '/api/') !== false || strpos($uri, '/wp-json/') !== false) {
            return true;
        }

        return false;
    }

    /**
     * Sends HTTP 503 lock response and terminates script execution.
     *
     * @param array $opts
     * @param bool $isJson
     * @param bool $terminate
     * @return void
     */
    public static function sendLockResponse(array $opts = [], bool $isJson = false, bool $terminate = true): void
    {
        if (!headers_sent()) {
            http_response_code(503);
            $headers = self::getLockHeaders((int)($opts['retryAfter'] ?? 3600));
            foreach ($headers as $k => $v) {
                header("{$k}: {$v}");
            }
        }

        if ($isJson) {
            if (!headers_sent()) {
                header('Content-Type: application/json; charset=utf-8');
            }
            $payload = [
                'error' => 'service_locked',
                'code' => $opts['code'] ?? 'DEVGUARD_LOCKED',
                'title' => $opts['title'] ?? 'Service Temporarily Locked',
                'message' => $opts['message'] ?? 'This service is currently unavailable.',
                'retryAfter' => (int)($opts['retryAfter'] ?? 3600),
                'appName' => $opts['appName'] ?? null,
            ];
            echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        } else {
            if (!headers_sent()) {
                header('Content-Type: text/html; charset=utf-8');
            }
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
            echo self::generateLockHtml($opts);
        }

        if ($terminate) {
            exit;
        }
    }
}
