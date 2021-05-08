<?php
require '../vendor/autoload.php';
header("Access-Control-Allow-Origin: *");
use League\OAuth2\Client\Provider\Google;

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__, '../.env');
$dotenv->load();

session_start();

header('Content-Type: application/json');
$DGT = new DGAuth\DGToken();

// $DGT->generateCerts();

$path_only = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($path_only == "/jwks") {
    echo $DGT->jwks();
} 
elseif ($path_only == '/login' || isset($_GET['state'])) {
    $GL = new DGAuth\GoogleLogin();

    $provider = new Google([
        'clientId'     => $_ENV['GOOGLE_CLIENT_ID'],
        'clientSecret' => $_ENV['GOOGLE_CLIENT_SECRET'],
        'redirectUri'  => $_ENV['GOOGLE_REDIRECT'],
    ]);
    
    $GL->login($provider);
    header("Location: ".$_ENV['LOGIN_REDIRECT']);
} elseif($path_only== '/refresh') {
    if(isset($_GET['refreshToken'])){
        $token = $_GET['refreshToken'];
    } elseif (isset($_COOKIE['refreshToken'])) {
        $token = $_COOKIE['refreshToken'];
    } else {
        echo json_encode(['error'=>'no token']);
        die();
    }
    echo $DGT->generateTokenFromRefreshToken($token);
}
