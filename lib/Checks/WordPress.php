<?php

class WordPressCheck
{
    public static function run(Http $http, string $base, array $root): array
    {
        $findings = [];

        $version = self::detectVersion($http, $base, $root);
        if ($version) {
            $findings[] = [
                'severity' => 'Low',
                'title'    => 'WordPress version disclosed',
                'detail'   => 'Detected WordPress ' . $version . '.',
                'attack'   => 'Lets attacker map version to specific core CVEs.',
                'fix'      => 'Remove the <meta name="generator"> tag, hide /readme.html, strip ?ver= from enqueued assets.',
            ];
        }

        $plugins = self::detectPlugins($root['body'] ?? '');
        $vulnDb  = self::loadVulnDb();

        foreach ($plugins as $slug => $pluginVersion) {
            if (isset($vulnDb[$slug])) {
                foreach ($vulnDb[$slug] as $vuln) {
                    if (self::versionAffected($pluginVersion, $vuln['affected'] ?? '')) {
                        $findings[] = [
                            'severity' => $vuln['severity'] ?? 'Medium',
                            'title'    => "Vulnerable plugin: {$slug}" . ($pluginVersion ? " v{$pluginVersion}" : ''),
                            'detail'   => $vuln['title'] . (isset($vuln['cve']) ? " ({$vuln['cve']})" : ''),
                            'attack'   => $vuln['attack'] ?? 'See CVE description.',
                            'fix'      => $vuln['fix'] ?? "Update {$slug} to a patched version.",
                        ];
                    }
                }
            }
        }

        $xmlrpc = $http->get($base . '/xmlrpc.php');
        if (($xmlrpc['status'] ?? 0) === 405 || str_contains($xmlrpc['body'] ?? '', 'XML-RPC server accepts POST')) {
            $findings[] = [
                'severity' => 'Medium',
                'title'    => 'xmlrpc.php enabled',
                'detail'   => '/xmlrpc.php is reachable.',
                'attack'   => 'system.multicall enables credential brute-forcing at scale; pingback can be used for SSRF/DDoS amplification.',
                'fix'      => 'Disable XML-RPC unless you need it (Disable XML-RPC plugin or block in webserver).',
            ];
        }

        $rest = $http->get($base . '/wp-json/wp/v2/users');
        if (($rest['status'] ?? 0) === 200 && str_contains($rest['body'] ?? '', '"slug"')) {
            $findings[] = [
                'severity' => 'Medium',
                'title'    => 'User enumeration via REST API',
                'detail'   => '/wp-json/wp/v2/users returns user list.',
                'attack'   => 'Attacker harvests usernames, then targets them with password spraying.',
                'fix'      => 'Restrict REST API users endpoint (e.g. Disable REST API plugin, or filter rest_endpoints).',
            ];
        }

        $readme = $http->get($base . '/readme.html');
        if (($readme['status'] ?? 0) === 200 && str_contains($readme['body'] ?? '', 'WordPress')) {
            $findings[] = [
                'severity' => 'Low',
                'title'    => '/readme.html accessible',
                'detail'   => 'Default WordPress readme is exposed.',
                'attack'   => 'Discloses WP version (helps target version CVEs).',
                'fix'      => 'Delete or block /readme.html.',
            ];
        }

        return $findings;
    }

    private static function detectVersion(Http $http, string $base, array $root): ?string
    {
        $body = $root['body'] ?? '';
        if (preg_match('/<meta name="generator" content="WordPress\s+([\d.]+)"/i', $body, $m)) {
            return $m[1];
        }
        $feed = $http->get($base . '/feed/');
        if (preg_match('/<generator>https?:\/\/wordpress\.org\/\?v=([\d.]+)<\/generator>/i', $feed['body'] ?? '', $m)) {
            return $m[1];
        }
        return null;
    }

    private static function detectPlugins(string $body): array
    {
        $plugins = [];
        if (preg_match_all('#/wp-content/plugins/([a-z0-9\-_]+)/[^\'"\s]*?(?:\?ver=([\d.]+))?#i', $body, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $slug = strtolower($m[1]);
                $ver  = $m[2] ?? '';
                if (!isset($plugins[$slug]) || ($ver && !$plugins[$slug])) {
                    $plugins[$slug] = $ver;
                }
            }
        }
        return $plugins;
    }

    private static function loadVulnDb(): array
    {
        $path = __DIR__ . '/../../data/wp_plugin_vulns.json';
        if (!is_file($path)) return [];
        $data = json_decode(file_get_contents($path), true);
        return is_array($data) ? $data : [];
    }

    private static function versionAffected(string $detected, string $constraint): bool
    {
        if ($constraint === '' || $constraint === '*') return true;
        if ($detected === '') return true;

        if (preg_match('/^<=?\s*([\d.]+)$/', $constraint, $m)) {
            $op = str_contains($constraint, '=') ? '<=' : '<';
            return version_compare($detected, $m[1], $op);
        }
        if (preg_match('/^<\s*([\d.]+)$/', $constraint, $m)) {
            return version_compare($detected, $m[1], '<');
        }
        return $detected === $constraint;
    }
}
