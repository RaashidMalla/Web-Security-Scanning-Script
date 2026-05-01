<?php
require_once __DIR__ . '/Http.php';
require_once __DIR__ . '/Checks/Headers.php';
require_once __DIR__ . '/Checks/ExposedFiles.php';
require_once __DIR__ . '/Checks/Laravel.php';
require_once __DIR__ . '/Checks/WordPress.php';

class Scanner
{
    private string $base;
    private Http $http;

    public function __construct(string $target)
    {
        $this->base = rtrim($target, '/');
        $this->http = new Http();
    }

    public function run(): array
    {
        $root        = $this->http->get($this->base . '/');
        $fingerprint = $this->fingerprint($root);

        $findings = [];
        $findings = array_merge($findings, HeadersCheck::run($root));
        $findings = array_merge($findings, ExposedFilesCheck::run($this->http, $this->base));

        if ($fingerprint['stack'] === 'Laravel') {
            $findings = array_merge($findings, LaravelCheck::run($this->http, $this->base, $root));
        }
        if ($fingerprint['stack'] === 'WordPress') {
            $findings = array_merge($findings, WordPressCheck::run($this->http, $this->base, $root));
        }

        usort($findings, fn($a, $b) => self::sevWeight($b['severity']) - self::sevWeight($a['severity']));

        return [
            'target'      => $this->base,
            'fingerprint' => $fingerprint,
            'findings'    => $findings,
        ];
    }

    private function fingerprint(array $root): array
    {
        $body    = $root['body'] ?? '';
        $headers = $root['headers'] ?? [];
        $stack   = 'Unknown';
        $version = null;

        $cookies = strtolower(implode(' ', array_filter(array_map(
            fn($k, $v) => strtolower($k) === 'set-cookie' ? $v : '',
            array_keys($headers), array_values($headers)
        ))));

        if (str_contains($cookies, 'laravel_session') || str_contains($cookies, 'xsrf-token')) {
            $stack = 'Laravel';
        } elseif (preg_match('/<meta name="generator" content="WordPress\s*([^"]*)"/i', $body, $m)) {
            $stack   = 'WordPress';
            $version = trim($m[1]);
        } elseif (str_contains($body, '/wp-content/') || str_contains($body, '/wp-includes/')) {
            $stack = 'WordPress';
        }

        return ['stack' => $stack, 'version' => $version];
    }

    private static function sevWeight(string $sev): int
    {
        return match (strtolower($sev)) {
            'critical' => 4,
            'high'     => 3,
            'medium'   => 2,
            'low'      => 1,
            default    => 0,
        };
    }
}
