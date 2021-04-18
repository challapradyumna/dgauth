<?php
namespace DGAuth;
use League\OAuth2\Client\Provider\Google;
class GoogleLogin {
    function login($provider) {
        
        if (!empty($_GET['error'])) {
        
            // Got an error, probably user denied access
            exit('Got error: ' . htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8'));
        
        } elseif (empty($_GET['code'])) {
        
            // If we don't have an authorization code then get one
            $authUrl = $provider->getAuthorizationUrl(['prompt' => 'consent','access_type'=>'offline']);
            $_SESSION['oauth2state'] = $provider->getState();
            header('Location: ' . $authUrl);
            exit;
        
        } elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {
        
            // State is invalid, possible CSRF attack in progress
            unset($_SESSION['oauth2state']);
            exit('Invalid state');
        
        } else {
        
            // Try to get an access token (using the authorization code grant)
            $token = $provider->getAccessToken('authorization_code', [
                'code' => $_GET['code']
            ]);
        
            // Optional: Now you have a token you can look up a users profile data
            try {
        
                // We got an access token, let's now get the owner details
                $ownerDetails = $provider->getResourceOwner($token);
        
                // Use these details to create a new profile
                printf('Hello %s!', $ownerDetails->getFirstName());
        
            } catch (Exception $e) {
        
                // Failed to get user details
                exit('Something went wrong: ' . $e->getMessage());
        
            }
            echo "<br/>";
            // Use this to interact with an API on the users behalf
            echo $token->getToken();
            echo "<br/>";
            // Use this to get a new access token if the old one expires
            echo $token->getRefreshToken();
            echo "<br/>";
            // Unix timestamp at which the access token expires
            echo $token->getExpires();
        }echo "<br/>";
        
    }
}