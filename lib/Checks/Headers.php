<?php

class HeadersCheck
{
    public static function run(array $response): array
    {
        $h = $response['headers'] ?? [];
        $findings = [];

        $expected = [
            'strict-transport-security' => [
                'severity' => 'Medium',
                'title'    => 'Missing HSTS header',
                'detail'   => 'No Strict-Transport-Security header.',
                'attack'   => 'SSL stripping / man-in-the-middle on first request can downgrade HTTPS.',
                'fix'      => 'Send: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            ],
            'content-security-policy' => [
                'severity' => 'Medium',
                'title'    => 'Missing Content-Security-Policy',
                'detail'   => 'No CSP defined.',
                'attack'   => 'Reflected/Stored XSS executes freely; no inline-script restriction.',
                'fix'      => "Add a CSP, e.g. default-src 'self'; script-src 'self'",
            ],
            'x-frame-options' => [
                'severity' => 'Low',
                'title'    => 'Missing X-Frame-Options',
                'detail'   => 'Page can be embedded in iframes.',
                'attack'   => 'Clickjacking: attacker overlays your UI inside their page.',
                'fix'      => 'Send X-Frame-Options: DENY (or use frame-ancestors in CSP).',
            ],
            'x-content-type-options' => [
                'severity' => 'Low',
                'title'    => 'Missing X-Content-Type-Options',
                'detail'   => 'Browser MIME-sniffing is enabled.',
                'attack'   => 'MIME confusion can turn an uploaded .jpg into executable JS.',
                'fix'      => 'Send X-Content-Type-Options: nosniff',
            ],
            'referrer-policy' => [
                'severity' => 'Low',
                'title'    => 'Missing Referrer-Policy',
                'detail'   => 'Default referrer leakage.',
                'attack'   => 'Sensitive URLs (tokens in query strings) leak to third parties.',
                'fix'      => 'Send Referrer-Policy: strict-origin-when-cross-origin',
            ],
        ];

        foreach ($expected as $name => $f) {
            if (!isset($h[$name])) {
                $findings[] = $f;
            }
        }

        if (isset($h['server']) && preg_match('/\d/', $h['server'])) {
            $findings[] = [
                'severity' => 'Low',
                'title'    => 'Server version disclosure',
                'detail'   => 'Server header exposes version: ' . $h['server'],
                'attack'   => 'Attackers fingerprint exact server build to look up matching CVEs.',
                'fix'      => 'Hide server tokens (e.g. ServerTokens Prod in Apache, server_tokens off in nginx).',
            ];
        }

        if (isset($h['x-powered-by'])) {
            $findings[] = [
                'severity' => 'Low',
                'title'    => 'X-Powered-By disclosure',
                'detail'   => 'Reveals: ' . $h['x-powered-by'],
                'attack'   => 'Same as server version disclosure: helps target known CVEs.',
                'fix'      => 'In PHP set expose_php=Off; in nginx remove the header.',
            ];
        }

        return $findings;
    }
}
