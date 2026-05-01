<?php

class ExposedFilesCheck
{
    private const PATHS = [
        '/.env' => [
            'severity' => 'Critical',
            'signature' => 'APP_KEY',
            'title'    => '.env file exposed',
            'detail'   => 'Application .env file is publicly accessible.',
            'attack'   => 'Reveals DB credentials, APP_KEY, mail credentials, third-party API keys. Full takeover likely.',
            'fix'      => 'Move .env outside docroot or block via webserver config. Rotate every secret it contained.',
        ],
        '/.git/config' => [
            'severity' => 'Critical',
            'signature' => '[core]',
            'title'    => '.git directory exposed',
            'detail'   => 'Git repository readable from the web.',
            'attack'   => 'Attacker dumps the whole repo (git-dumper), recovers source + secrets in commit history.',
            'fix'      => "Don't deploy the .git folder. Block /.git/ in webserver config.",
        ],
        '/.DS_Store' => [
            'severity' => 'Low',
            'signature' => 'Bud1',
            'title'    => '.DS_Store leaked',
            'detail'   => 'macOS metadata file exposes directory listing.',
            'attack'   => 'Reveals filenames the developer didn\'t intend to publish.',
            'fix'      => 'Delete the file and add to .gitignore.',
        ],
        '/composer.lock' => [
            'severity' => 'Medium',
            'signature' => '"packages":',
            'title'    => 'composer.lock exposed',
            'detail'   => 'Dependency versions disclosed.',
            'attack'   => 'Attacker maps installed packages to known CVEs (CVE-targeting).',
            'fix'      => 'Block /composer.lock and /composer.json in webserver config.',
        ],
        '/package.json' => [
            'severity' => 'Low',
            'signature' => '"dependencies"',
            'title'    => 'package.json exposed',
            'detail'   => 'JS dependency list disclosed.',
            'attack'   => 'Same as composer.lock — fingerprint vulnerable JS libs.',
            'fix'      => 'Block from public access.',
        ],
        '/phpinfo.php' => [
            'severity' => 'High',
            'signature' => 'PHP Version',
            'title'    => 'phpinfo() page exposed',
            'detail'   => 'phpinfo() is publicly accessible.',
            'attack'   => 'Discloses full PHP config, env vars, paths — gold mine for attackers.',
            'fix'      => 'Delete the file.',
        ],
        '/wp-config.php.bak' => [
            'severity' => 'Critical',
            'signature' => 'DB_PASSWORD',
            'title'    => 'WordPress config backup exposed',
            'detail'   => 'wp-config.php.bak is downloadable.',
            'attack'   => 'Database credentials in cleartext — direct DB access.',
            'fix'      => 'Delete the backup; rotate DB password.',
        ],
        '/wp-config.php~' => [
            'severity' => 'Critical',
            'signature' => 'DB_PASSWORD',
            'title'    => 'WordPress config swap file exposed',
            'detail'   => 'Editor backup of wp-config.php is downloadable.',
            'attack'   => 'Same as wp-config.php.bak.',
            'fix'      => 'Delete the backup; rotate DB password.',
        ],
        '/backup.zip' => [
            'severity' => 'High',
            'signature' => 'PK',
            'title'    => 'Backup archive exposed',
            'detail'   => 'A backup.zip file is downloadable.',
            'attack'   => 'Full source / DB dump can be downloaded anonymously.',
            'fix'      => 'Move backups out of webroot.',
        ],
    ];

    public static function run(Http $http, string $base): array
    {
        $findings = [];
        foreach (self::PATHS as $path => $f) {
            $r = $http->get($base . $path);
            if (($r['status'] ?? 0) === 200 && self::matches($r['body'] ?? '', $f['signature'])) {
                unset($f['signature']);
                $f['detail'] .= ' (' . $base . $path . ')';
                $findings[] = $f;
            }
        }
        return $findings;
    }

    private static function matches(string $body, string $signature): bool
    {
        if ($signature === '') return true;
        return str_contains($body, $signature);
    }
}
