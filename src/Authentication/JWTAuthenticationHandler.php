<?php

namespace Firesphere\GraphQLJWT\Authentication;

use Firesphere\GraphQLJWT\Helpers\HeaderExtractor;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\ORM\ValidationException;
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
            // Validate the token. This is critical for security
            $member = $this->authenticator->authenticate(['token' => $matches[1]], $request);
        }

        if ($member) {
            $this->logIn($member);
        }

        return $member;
    }

    /**
     * Authenticate on every run, based on the header, not relying on sessions or cookies
     * JSON Web Tokens are stateless
     *
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
     * @throws ValidationException
     */
    public function logOut(HTTPRequest $request = null)
    {
        // A token can actually not be invalidated, but let's invalidate it's unique ID
        // A member actually can be null though!
        if ($request !== null) { // If we don't have a request, we're most probably in test mode
            $member = Security::getCurrentUser();
            if ($member) {
                // Set the unique ID to 0, as it can't be nullified due to indexes.
                $member->JWTUniqueID = 0;
                $member->write();
            }
        }
        // Empty the current user and pray to god it's not valid anywhere else anymore :)
        Security::setCurrentUser();
    }
}
