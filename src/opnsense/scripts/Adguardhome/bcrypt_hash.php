#!/usr/local/bin/php
<?php
/**
 * Derive the bcrypt hash of the managed AdGuard Home service account.
 *
 * AdGuard Home stores its administrators as bcrypt hashes and Go accepts the
 * $2y$ prefix.  Python 3.13 dropped the crypt module and the plugin adds no
 * third party dependency, so the hash is produced by the PHP interpreter that
 * OPNsense always ships.  With a fixed 22 character salt crypt() is
 * deterministic, which keeps the derived account reproducible on both nodes.
 *
 * Reads {"password": "...", "salt": "..."} as JSON on standard input and
 * prints the hash.
 */

function fail(string $message): void
{
    fwrite(STDERR, $message . PHP_EOL);
    exit(1);
}

$input = stream_get_contents(STDIN);
if ($input === false || trim($input) === '') {
    fail('No input was provided.');
}
$request = json_decode($input, true);
if (!is_array($request)) {
    fail('The input is not a JSON object.');
}
$password = $request['password'] ?? null;
$salt = $request['salt'] ?? null;
if (!is_string($password) || $password === '') {
    fail('The password is missing or invalid.');
}
if (!is_string($salt) || preg_match('#^[./A-Za-z0-9]{22}$#', $salt) !== 1) {
    fail('The salt is missing or invalid.');
}
$hash = crypt($password, '$2y$10$' . $salt);
if (!is_string($hash) || strlen($hash) !== 60 || !str_starts_with($hash, '$2y$10$')) {
    fail('The bcrypt hash could not be derived.');
}
echo $hash;
