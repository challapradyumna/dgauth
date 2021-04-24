# Auth library for DGraph with JWK's endpoint


Standalone library that supports generating self-signed tokens for Authenticating against DGraph and a JWKs endpoint
## Configure

Generate key pairs into backend/keys directory

Key pair should have the same name with .key and .pub for private and public key respectively

If you are familiar with php there is a handy function in DGToken file to generate pairs and push them to keys directory. 

Copy .env.sample to .env fill up the variables with appropriate variables.

Currently the library only supports a Google based login

Username / Password based and other OAuth providers are planned for future.


## Running (Kubernetes)

* dgraph-single.yaml for launching a single node dgraph for testing
* backend/Dockerfile - Build the container locally and push it to wherever the kube cluster can reach to pull it
* backend/deploy.yaml - Simple deployment with a service to access DGAuth within the cluster
* schema.graphql - Simple schema with Auth configuration which works with the above setup

## Building

```
php -s localhost:8080 -t backend/src
```

There are 2 endpoints available:

/jwks - Returns a standard json formatted jwks which are stored in backend/keys

/login - Takes you through OAuth authentication of google and generate a refresh and access token with one of the self signed cert in keys directory.
