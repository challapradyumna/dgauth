<?php

namespace DGAuth;

use GuzzleHttp\Client;
use \Firebase\JWT\JWT;
use \Firebase\JWT\JWK;
use phpseclib3\File\X509;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\PublicKeyLoader;

class DGToken
{
    private $client;

    public function __construct()
    {
        $this->client = new Client([
            'base_uri' => $_ENV['DGRAPH_GQL'],
        ]);
    }
    

    public function graphqlQuery($query, $accessToken='')
    {
        $headers = [];
        if ($accessToken != "") {
            $headers =  array($_ENV['DGRAPH_HEADER'] => $accessToken);
        }
        $response = $this->client->request(
            'POST',
            '',
            [
            'headers' => $headers,
            'json' => [
              'query' => $query
            ]
        ]
        );

        return json_decode($response->getBody()->getContents(), true);
    }

    public function createUser($username, $type)
    {
        $dateTime = date(DATE_RFC3339);
        $query = <<<GQL
        mutation (){
            addUser(input: { username: "$username" , isType : $type, password: "password123", createdAt:"$dateTime",updatedAt:"$dateTime" }) { 
                user {
                    username
                }
            }
        }
        GQL;
        return $this->graphqlQuery($query);
    }

    public function getUser($username)
    {
        $query = <<<GQL
        query {
            getUser(username: "$username") {
                username
                isType
                phone {
                    number
                }
            }
        }
        GQL;
        $payload = array(
            "iss" => "dgauth",
            "aud" => $_ENV['DGRAPH_AUD'],
            "sub" => $username,
            $_ENV['DGRAPH_NAMESPACE'] => [
                "username"=> $username,
                "isAuthenticated"=>"true"
            ],
            "iat" => time(),
            "nbf" => time(),
            "exp" => time()+10
        );
        $token = $this->generateToken($payload);
        $user = $this->graphqlQuery($query, $token);

        if (!isset($user['data']['getUser'])) {
            $user = $this->createUser($username, "USER");
            $user = $this->getUser($username);
        }
        return $user;
    }

    public function generateRefreshToken($username, $role)
    {
        $payload = array(
            "iss" => "dgauth",
            "aud" => $_ENV['DGRAPH_AUD'],
            "sub" => $username,
            "iat" => time(),
            "nbf" => time(),
            "exp" => time()+(int)$_ENV['REFRESH_TOKEN_LT']
        );
        return $this->generateToken($payload);
    }

    public function generateAccessToken($username, $role)
    {
        $payload = array(
            "iss" => "dgauth",
            "aud" => $_ENV['DGRAPH_AUD'],
            "sub" => $username,
            $_ENV['DGRAPH_NAMESPACE'] => [
                "username"=> $username,
                "isAuthenticated"=>"true",
                "role"=>$role
            ],
            "iat" => time(),
            "nbf" => time(),
            "exp" => time()+(int)$_ENV['ACCESS_TOKEN_LT']
        );
        return $this->generateToken($payload);
    }


    public function generateTokenFromRefreshToken($refreshToken) {
        $jwks = $this->jwks();
        $jwks = json_decode($jwks,true);
        try {
            $decodedToken = JWT::decode($refreshToken, JWK::parseKeySet($jwks), ['RS256']);
            $newAccessToken = $this->generateAccessToken($decodedToken->sub,"USER");
            \setcookie("accessToken",$newAccessToken,time()+60*60*24*30,"/");
            echo json_encode(["accessToken"=>$newAccessToken]);
        } catch(\Exception $e) {
            $error["error"] = "Could not issue access token";
            setcookie("refreshToken", "", time() - 3600);
            setcookie("accessToken", "", time() - 3600);
            header("Location: ".$_ENV['LOGIN_REDIRECT']);
        }
        
    }
    
    public function generateToken($payload)
    {
        $files = glob(realpath(__DIR__.'/..')."/keys/*.key");
        $random_key = array_rand($files);
        $privateKey = file_get_contents($files[$random_key]);
        $pubKeyFileName = substr($files[$random_key], 0, -3)."pub";
        $publicKey = file_get_contents($pubKeyFileName);
        $publicCert = openssl_pkey_get_public($publicKey);
        $publicCertData = openssl_pkey_get_details($publicCert);
        $kid = $this->base64url_encode(md5($publicCertData["rsa"]["n"]));
        $jwt = JWT::encode($payload, $privateKey, 'RS256', $kid);
        return $jwt;
    }
    public function base64url_encode($data)
    {
        $b64 = base64_encode($data);
        if ($b64 === false) {
            return false;
        }
        // Convert Base64 to Base64URL by replacing “+” with “-” and “/” with “_”
        $url = strtr($b64, '+/', '-_');
        return rtrim($url, '=');
    }
    
    public function jwks()
    {
        $keys = array("keys"=>[]);
        $files = glob(realpath(__DIR__.'/..')."/keys/*.pub");
        foreach ($files as $file) {
            $key = ["alg"=>"RS256","kty"=>"RSA","use"=>"sig"];
            $pubCert = file_get_contents($file);
            
            $publicCert = openssl_pkey_get_public($pubCert);
            $publicCertData = openssl_pkey_get_details($publicCert);
            
            $key["n"] = $this->base64url_encode($publicCertData["rsa"]["n"]);
            $key["e"] = $this->base64url_encode($publicCertData["rsa"]["e"]);
            $key["kid"] = $this->base64url_encode(md5($publicCertData["rsa"]["n"]));
            \array_push($keys["keys"], $key);
        }
        return json_encode($keys);
    }

    public function generateCerts()
    {
        $privKey = RSA::createKey();
        $privKey = $privKey->withPadding(RSA::SIGNATURE_PKCS1);
        $pubKey = $privKey->getPublicKey();
        $fileName = bin2hex(random_bytes(16));
        file_put_contents('../keys/'.$fileName.".key", $privKey);
        file_put_contents('../keys/'.$fileName.".pub", $pubKey);
    }
}
