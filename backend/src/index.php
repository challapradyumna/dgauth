<?php
require '../vendor/autoload.php';

use League\OAuth2\Client\Provider\Google;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__, '../.env');
$dotenv->load();

session_start();

$DGT = new DGAuth\DGToken();

// $DGT->generateCerts();

$path_only = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path_only == "/jwks") {
    header('Content-Type: application/json');
    echo $DGT->jwks();
} elseif ($path_only == "/genToken") {
    echo $DGT->generateToken();
} elseif ($path_only == '/login' || isset($_GET['state'])) {
    $GL = new DGAuth\GoogleLogin();

    $provider = new Google([
        'clientId'     => $_ENV['GOOGLE_CLIENT_ID'],
        'clientSecret' => $_ENV['GOOGLE_CLIENT_SECRET'],
        'redirectUri'  => $_ENV['GOOGLE_REDIRECT'],
    ]);

    $GL->login($provider);
}
