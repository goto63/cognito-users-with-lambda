'use strict';

var jwt = require('jsonwebtoken');
var request = require('request');
var jwkToPem = require('jwk-to-pem');

var pems;
var iss = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_1XxgM7Ia4";

exports.hello = function (event, context) {
    if (!pems) {
        //Download the JWKs and save it as PEM
        request({
            url: iss + '/.well-known/jwks.json',
            json: true
        }, function (error, response, body) {
            if (!error && response.statusCode === 200) {
                pems = {};
                var keys = body['keys'];
                for (var i = 0; i < keys.length; i++) {
                    //Convert each key to PEM
                    var key_id = keys[i].kid;
                    var modulus = keys[i].n;
                    var exponent = keys[i].e;
                    var key_type = keys[i].kty;
                    var jwk = {kty: key_type, n: modulus, e: exponent};
                    var pem = jwkToPem(jwk);
                    pems[key_id] = pem;
                }
                //Now continue with validating the token
                ValidateToken(pems, event, context);
            } else {
                //Unable to download JWKs, fail the call
                context.fail("error");
            }
        });
    } else {
        //PEMs are already downloaded, continue with validating the token
        ValidateToken(pems, event, context);
    }
};

function ValidateToken(pems, event, context) {
    var token = event.authorizationToken;
    //Fail if the token is not jwt
    var decodedJwt = jwt.decode(token, {complete: true});
    if (!decodedJwt) {
        console.log("Not a valid JWT token");
        context.fail("Unauthorized");
        return;
    }

    //Fail if token is not from your User Pool
    if (decodedJwt.payload.iss != iss) {
        console.log("invalid issuer");
        context.fail("Unauthorized");
        return;
    }

    //Reject the jwt if it's not an 'Access Token'
    if (decodedJwt.payload.token_use != 'access') {
        console.log("Not an access token");
        context.fail("Unauthorized");
        return;
    }

    //Get the kid from the token and retrieve corresponding PEM
    var kid = decodedJwt.header.kid;
    var pem = pems[kid];
    if (!pem) {
        console.log('Invalid access token');
        context.fail("Unauthorized");
        return;
    }

    //Verify the signature of the JWT token to ensure it's really coming from your User Pool
    jwt.verify(token, pem, {issuer: iss}, function (err, payload) {
        if (err) {
            console.log('verify failed');
            context.fail("Unauthorized");
        } else {
            context.succeed("authoricated!!!");
        }
    });
}
