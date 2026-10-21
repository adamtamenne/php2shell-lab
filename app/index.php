<?php
// Lab landing page - confirms the environment is vulnerable
echo "<h1>php2shell Lab</h1>";
echo "<p>PHP " . phpversion() . " / " . php_sapi_name() . "</p>";
echo "<p>memory_limit: " . ini_get('memory_limit') . "</p>";
echo "<p>post_max_size: " . ini_get('post_max_size') . "</p>";
echo "<p>session.upload_progress.enabled: " . ini_get('session.upload_progress.enabled') . "</p>";
echo "<hr>";
echo "<h2>Exercises</h2>";
echo "<ul>";
echo "<li><a href='/info.php'>Full phpinfo()</a></li>";
echo "<li><a href='/oom_target.php'>CVE-2026-109618: OOM target</a></li>";
echo "<li><a href='/stale_target.php'>CVE-2026-109619: Stale state target</a></li>";
echo "</ul>";
