<?php

namespace Firesphere\GraphQLJWT\Middleware;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Control\HTTPResponse;
use SilverStripe\Control\Middleware\HTTPMiddleware;
use SilverStripe\SessionManager\Middleware\LoginSessionMiddleware;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticationHandler;

class JWTLoginSessionMiddleware extends LoginSessionMiddleware
{
    /**
     * @param HTTPRequest $request
     * @param callable $delegate
     * @return HTTPResponse
     */
    public function process(HTTPRequest $request, callable $delegate)
    {
        // if the user is using JWT token for authenticating, then nothing to do with the LoginSession
        if (JWTAuthenticationHandler::getAuthorizationHeader($request)) {
            return $delegate($request);
        }

        return parent::process($request, $delegate);
    }
}
