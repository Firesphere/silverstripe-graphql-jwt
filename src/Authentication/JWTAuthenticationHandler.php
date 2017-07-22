<?php

namespace Firesphere\GraphQLJWT;

use SilverStripe\Control\HTTPRequest;
use SilverStripe\Security\AuthenticationHandler;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * Class JWTAuthenticationHandler
 *
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

    /**
     * @param HTTPRequest $request
     * @return null|Member
     * @throws \OutOfBoundsException
     * @throws \BadMethodCallException
     */
    public function authenticateRequest(HTTPRequest $request)
    {
        $matches = HeaderExtractor::getAuthorizationHeader($request);
        // Get the default user currently logged in via a different way, could be BasicAuth/normal login
        $member = Security::getCurrentUser();

        if (!empty($matches[1])) {
            $member = $this->authenticator->authenticate(['token' => $matches[1]], $request);
        }

        if ($member) {
            $this->logIn($member);
        }

        return $member;
    }

    /**
     * @param Member $member
     * @param bool $persistent
     * @param HTTPRequest|null $request
     */
    public function logIn(Member $member, $persistent = false, HTTPRequest $request = null)
    {
        Security::setCurrentUser($member);
    }

    /**
     * @param HTTPRequest|null $request
     */
    public function logOut(HTTPRequest $request = null)
    {
        // A token can actually not be invalidated, only blacklisted
        if ($request !== null) {
            $request->getSession()->clear('jwt');
        }
        Security::setCurrentUser(null);
    }
}
