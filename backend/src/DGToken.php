<?php

namespace DGAuth;

use GuzzleHttp\Client;
use \Firebase\JWT\JWT;
use phpseclib3\File\X509;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;

class DGToken  {

    private $client;

    function DGToken() {
        $this->client = new Client([
            // Base URI is used with relative requests
            'base_uri' => $_ENV['DGRAPH_GQL'],
            // You can set any number of default request options.
            'timeout'  => 2.0,
        ]);
    }

    function generateToken() {
        $files = glob(realpath(__DIR__.'/..')."/keys/*.key");
        $random_key = array_rand($files);
        $privateKey = file_get_contents($files[$random_key]);
        $pubKeyFileName = substr($files[$random_key],0,-3)."pub";
        $publicKey = file_get_contents($pubKeyFileName);
        $publicCertFilename = $pubKeyFileName = substr($files[$random_key],0,-3)."crt";
        $publicCert = file_get_contents($publicCertFilename);

        $payload = array(
            "iss" => "dgraph-io",
            "aud" => "dgraph-io",
            "https://dgraph.io/jwt/claims" => [
                "USERNAME"=> "challapradyumna",
                "IS_LOGGED_IN"=>"true",
                "USERROLE"=>"ADMINISTRATOR"
            ],
            "iat" => time(),
            "nbf" => time()
        );
        $x509 = new X509();
        $x509->loadX509($publicCert);
        $kid = $this->base64url_encode($x509->getExtension("id-ce-authorityKeyIdentifier")['keyIdentifier']);
        $jwt = JWT::encode($payload, $privateKey, 'RS256',$kid);
        return $jwt;
    }
    function base64url_encode($data)
    {
        // First of all you should encode $data to Base64 string
        $b64 = base64_encode($data);

        // Make sure you get a valid result, otherwise, return FALSE, as the base64_encode() function do
        if ($b64 === false) {
            return false;
        }

        // Convert Base64 to Base64URL by replacing “+” with “-” and “/” with “_”
        $url = strtr($b64, '+/', '-_');

        // Remove padding character from the end of line and return the Base64URL result
        return rtrim($url, '=');
    }
    function jwks() {
        $keys = array("keys"=>[]);
        $files = glob(realpath(__DIR__.'/..')."/keys/*.crt");
        foreach($files as $file) {
            
            $key = ["alg"=>"RS256","kty"=>"RSA","use"=>"sig"];
            $pubCert = file_get_contents($file);

            $x509 = new X509();
            $x509->loadX509($pubCert);
            
            $publicCert = openssl_pkey_get_public((string)$x509->getPublicKey());
            $publicCertData = openssl_pkey_get_details($publicCert);
            // $parseData = openssl_x509_parse($pubCert);
            
            $key["n"] = $this->base64url_encode($publicCertData["rsa"]["n"]);
             $key["e"] = $this->base64url_encode($publicCertData["rsa"]["e"]);
             $key["kid"] = $this->base64url_encode($x509->getExtension("id-ce-authorityKeyIdentifier")['keyIdentifier']);//bin2hex((string)$x509->getExtension("id-ce-authorityKeyIdentifier"));
            \array_push($keys["keys"],$key);
        }
        return json_encode($keys);
    }

    function generateCerts() {
        $privKey = RSA::createKey();
        $privKey = $privKey->withPadding(RSA::SIGNATURE_PKCS1);
        $pubKey = $privKey->getPublicKey();

        $subject = new X509;
        $subject->setDNProp('admin@example.com', 'Test Cert Example Com');

        $subject->setPublicKey($pubKey);

        $issuer = new X509;
        $issuer->setPrivateKey($privKey);
        $issuer->setDN($subject->getDN());
        $kid = $issuer->computeKeyIdentifier((string)$pubKey);
        $issuer->setKeyIdentifier($kid);

        $x509 = new X509;
        $result = $x509->sign($issuer, $subject);
        $crt = $x509->saveX509($result);
        $fileName = bin2hex(random_bytes(16));
        file_put_contents('../keys/'.$fileName.".key",$privKey);
        file_put_contents('../keys/'.$fileName.".crt",$crt);
        file_put_contents('../keys/'.$fileName.".pub",$pubKey);
    }
}