<?php

class LaravelCheck
{
    public static function run(Http $http, string $base, array $root): array
    {
        $findings = [];

        $err = $http->get($base . '/this-route-should-not-exist-' . bin2hex(random_bytes(4)));
        $body = $err['body'] ?? '';
        if (
            str_contains($body, 'Whoops, looks like something went wrong')
            || str_contains($body, 'Illuminate\\')
            || preg_match('/laravel\/framework/i', $body)
        ) {
            if (
                str_contains($body, 'Stack trace')
                || str_contains($body, 'vendor/laravel')
                || str_contains($body, 'APP_KEY')
            ) {
                $findings[] = [
                    'severity' => 'Critical',
                    'title'    => 'Laravel debug mode enabled in production',
                    'detail'   => 'APP_DEBUG=true exposes stack traces and env vars on errors.',
                    'attack'   => 'Ignition RCE (CVE-2021-3129) on Laravel <8.4.2 + debug=true gives remote code execution. Even without RCE, env values leak.',
                    'fix'      => 'Set APP_DEBUG=false in production .env. Update laravel/framework and facade/ignition.',
                ];
            }
        }

        $telescope = $http->get($base . '/telescope');
        if (($telescope['status'] ?? 0) === 200 && str_contains($telescope['body'] ?? '', 'Telescope')) {
            $findings[] = [
                'severity' => 'High',
                'title'    => 'Laravel Telescope publicly accessible',
                'detail'   => '/telescope responds publicly.',
                'attack'   => 'Telescope shows requests, queries, jobs — sessions and tokens leak in plain view.',
                'fix'      => 'Restrict in TelescopeServiceProvider::gate() to authorized users only, or disable in production.',
            ];
        }

        $horizon = $http->get($base . '/horizon');
        if (($horizon['status'] ?? 0) === 200 && str_contains($horizon['body'] ?? '', 'Horizon')) {
            $findings[] = [
                'severity' => 'Medium',
                'title'    => 'Laravel Horizon publicly accessible',
                'detail'   => '/horizon dashboard is reachable.',
                'attack'   => 'Exposes queue internals, job payloads, failed jobs (often containing sensitive data).',
                'fix'      => 'Lock down via Horizon::auth() in HorizonServiceProvider.',
            ];
        }

        $debugbar = $http->get($base . '/_debugbar/open');
        if (($debugbar['status'] ?? 0) === 200) {
            $findings[] = [
                'severity' => 'High',
                'title'    => 'Laravel Debugbar exposed',
                'detail'   => '_debugbar endpoint responds.',
                'attack'   => 'Debugbar leaks queries, request data, session contents.',
                'fix'      => 'Set DEBUGBAR_ENABLED=false or remove barryvdh/laravel-debugbar from production.',
            ];
        }

        $rootBody = $root['body'] ?? '';
        if (preg_match('/Laravel\s+v?(\d+\.\d+(?:\.\d+)?)/i', $rootBody, $m)) {
            $findings[] = [
                'severity' => 'Low',
                'title'    => 'Laravel version disclosed',
                'detail'   => 'Detected Laravel ' . $m[1] . ' in page output.',
                'attack'   => 'Helps attacker target version-specific CVEs.',
                'fix'      => 'Remove version strings from public templates / error pages.',
            ];
        }

        return $findings;
    }
}
