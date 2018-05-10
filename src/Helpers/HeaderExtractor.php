<?php

namespace Firesphere\GraphQLJWT\Helpers;

use SilverStripe\Control\HTTPRequest;

class HeaderExtractor
{

    /**
     * @param HTTPRequest $request
     * @return array
     */
    public static function getAuthorizationHeader(HTTPRequest $request)
    {
        $authHeader = $request->getHeader('Authorization');
        if (!$authHeader && isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
            $authHeader = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
        }
        
        if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return $matches;
        }

        return [0, null];
    }
}
