<?php

namespace Firesphere\GraphQLJWT;

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
        if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return $matches;
        }
        return [0, null];
    }
}
