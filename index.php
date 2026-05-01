<?php
require_once __DIR__ . '/lib/Scanner.php';

$result = null;
$error  = null;
$target = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $target  = trim($_POST['target'] ?? '');
    $consent = isset($_POST['consent']);

    if (!$consent) {
        $error = 'You must confirm you are authorized to scan this target.';
    } elseif (!filter_var($target, FILTER_VALIDATE_URL)) {
        $error = 'Please enter a valid URL (including http:// or https://).';
    } else {
        try {
            $scanner = new Scanner($target);
            $result  = $scanner->run();
        } catch (Throwable $e) {
            $error = 'Scan failed: ' . $e->getMessage();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Web Vulnerability Scanner</title>
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
<div class="container">
    <h1>Web Vulnerability Scanner</h1>
    <p class="subtitle">Passive security checks for Laravel &amp; WordPress sites.</p>

    <div class="warning">
        <strong>Legal notice:</strong> Only scan websites you own or have written
        permission to test. Unauthorized scanning may violate computer-misuse
        laws in your country.
    </div>

    <form method="post" class="scan-form">
        <label for="target">Target URL</label>
        <input type="url" id="target" name="target" placeholder="https://example.com"
               value="<?= htmlspecialchars($target) ?>" required>

        <label class="checkbox">
            <input type="checkbox" name="consent" required>
            I confirm I am authorized to scan this target.
        </label>

        <button type="submit">Run Scan</button>
    </form>

    <?php if ($error): ?>
        <div class="error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <?php if ($result): ?>
        <h2>Scan Report &mdash; <?= htmlspecialchars($result['target']) ?></h2>

        <div class="meta">
            <span><strong>Detected stack:</strong> <?= htmlspecialchars($result['fingerprint']['stack']) ?></span>
            <?php if (!empty($result['fingerprint']['version'])): ?>
                <span><strong>Version:</strong> <?= htmlspecialchars($result['fingerprint']['version']) ?></span>
            <?php endif; ?>
            <span><strong>Findings:</strong> <?= count($result['findings']) ?></span>
        </div>

        <?php if (empty($result['findings'])): ?>
            <p class="ok">No issues detected by the passive checks.</p>
        <?php else: ?>
            <table class="findings">
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Issue</th>
                        <th>Detail</th>
                        <th>Attack vector</th>
                        <th>Fix</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach ($result['findings'] as $f): ?>
                    <tr class="sev-<?= htmlspecialchars(strtolower($f['severity'])) ?>">
                        <td><span class="badge"><?= htmlspecialchars($f['severity']) ?></span></td>
                        <td><?= htmlspecialchars($f['title']) ?></td>
                        <td><?= htmlspecialchars($f['detail']) ?></td>
                        <td><?= htmlspecialchars($f['attack']) ?></td>
                        <td><?= htmlspecialchars($f['fix']) ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    <?php endif; ?>
</div>
</body>
</html>
