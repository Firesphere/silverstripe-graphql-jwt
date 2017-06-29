<?php

namespace Firesphere\GraphQLJWT;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Security\AuthenticationHandler;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * Class JWTAuthenticationHandler
 * @todo refactor to the AppKernelStuff
 *
 * @package Firesphere\GraphQLJWT
 */
class JWTAuthenticationHandler implements AuthenticationHandler
{

    /**
     * @var JWTAuthenticator
     */
    protected $authenticator;

    /**
     * @return mixed
     */
    public function getAuthenticator()
    {
        return $this->authenticator;
    }

    /**
     * @param mixed $authenticator
     */
    public function setAuthenticator($authenticator)
    {
        $this->authenticator = $authenticator;
    }

    public function preRequest($request)
    {
        return $this->authenticateRequest($request);
    }

    public function postRequest()
    {
        return;
    }


    public function authenticateRequest(HTTPRequest $request)
    {
        $authHeader = $request->getHeader('Authorization');
        $member = null;
        if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
            $member = $this->authenticator->authenticate(['token' => $matches[1]], $request);
        }
        if ($member) {
            $this->logIn($member);
        } else {
            // Get the default user currently logged in via a different way, could be BasicAuth/normal login
            $member = Security::getCurrentUser();
        }

        return $member;
    }

    public function logIn(Member $member, $persistent = false, HTTPRequest $request = null)
    {
        Security::setCurrentUser($member);
    }

    public function logOut(HTTPRequest $request = null)
    {
        if ($request !== null) {
            $authHeader = $request->getHeader('Authorization');
            if ($authHeader && preg_match('/Bearer\s+(.*)$/i', $authHeader, $matches)) {
                $member = $this->authenticator->authenticate(['token' => $matches[1]], $request);
            }
            $request->getSession()->clear('jwt');
        }
        Security::setCurrentUser(null);
    }

}