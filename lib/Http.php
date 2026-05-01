<?php

class Http
{
    private const TIMEOUT    = 10;
    private const USER_AGENT = 'WeScanningScript/1.0 (+passive-vuln-scanner)';

    public function get(string $url): array
    {
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_TIMEOUT        => self::TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_USERAGENT      => self::USER_AGENT,
            CURLOPT_HEADER         => true,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $raw = curl_exec($ch);
        if ($raw === false) {
            $err = curl_error($ch);
            curl_close($ch);
            return ['status' => 0, 'headers' => [], 'body' => '', 'error' => $err, 'url' => $url];
        }

        $status     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $finalUrl   = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        curl_close($ch);

        $rawHeaders = substr($raw, 0, $headerSize);
        $body       = substr($raw, $headerSize);

        return [
            'status'  => $status,
            'headers' => $this->parseHeaders($rawHeaders),
            'body'    => $body,
            'url'     => $finalUrl,
        ];
    }

    private function parseHeaders(string $raw): array
    {
        $out  = [];
        $blocks = preg_split("/\r?\n\r?\n/", trim($raw));
        $last   = end($blocks);
        foreach (preg_split("/\r?\n/", $last) as $line) {
            if (str_contains($line, ':')) {
                [$k, $v] = explode(':', $line, 2);
                $k = strtolower(trim($k));
                $v = trim($v);
                if (isset($out[$k])) {
                    $out[$k] .= '; ' . $v;
                } else {
                    $out[$k] = $v;
                }
            }
        }
        return $out;
    }
}
