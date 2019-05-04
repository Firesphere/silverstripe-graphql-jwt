<?php

namespace Firesphere\GraphQLJWT\Helpers;

use SilverStripe\Control\HTTPRequest;
use \SilverStripe\Core\Environment;

class HeaderExtractor
{

    /**
     * @param HTTPRequest $request
     * @return array
     */
    public static function getAuthorizationHeader(HTTPRequest $request)
    {
        $authHeader = $request->getHeader('Authorization');
        if (!$authHeader) {
            $envVars = Environment::getVariables();
            if (isset($envVars['_SERVER']['REDIRECT_HTTP_AUTHORIZATION'])) {
                $authHeader = $envVars['_SERVER']['REDIRECT_HTTP_AUTHORIZATION'];
            }
        }
        
        if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            return $matches;
        }

        return [0, null];
    }
}
