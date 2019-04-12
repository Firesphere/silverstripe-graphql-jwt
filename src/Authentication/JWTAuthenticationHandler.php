<?php

namespace Firesphere\GraphQLJWT\Authentication;

use BadMethodCallException;
use Exception;
use Firesphere\GraphQLJWT\Extensions\MemberExtension;
use Firesphere\GraphQLJWT\Helpers\HeaderExtractor;
use OutOfBoundsException;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Security\AuthenticationHandler;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;

/**
 * Class JWTAuthenticationHandler
 *
 * @package Firesphere\GraphQLJWT
 */
class JWTAuthenticationHandler implements AuthenticationHandler
{
    use HeaderExtractor;

    /**
     * @var JWTAuthenticator
     */
    protected $authenticator;

    /**
     * @return JWTAuthenticator
     */
    public function getAuthenticator()
    {
        return $this->authenticator;
    }

    /**
     * @param JWTAuthenticator $authenticator
     * @return $this
     */
    public function setAuthenticator(JWTAuthenticator $authenticator)
    {
        $this->authenticator = $authenticator;
        return $this;
    }

    /**
     * @param HTTPRequest $request
     * @return null|Member
     * @throws OutOfBoundsException
     * @throws BadMethodCallException
     * @throws Exception
     */
    public function authenticateRequest(HTTPRequest $request)
    {
        // Check token
        $token = $this->getAuthorizationHeader($request);
        if (!$token) {
            return null;
        }

        // Validate the token. This is critical for security
        $member = $this
            ->getAuthenticator()
            ->authenticate(['token' => $token], $request);

        if ($member) {
            $this->logIn($member);
        }

        return $member;
    }

    /**
     * Authenticate on every run, based on the header, not relying on sessions or cookies
     * JSON Web Tokens are stateless
     *
     * @param Member           $member
     * @param bool             $persistent
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
        // A token can actually not be invalidated, but let's flush all valid tokens from the DB.
        // Note that log-out acts as a global logout (all devices)
        /** @var Member|MemberExtension $member */
        $member = Security::getCurrentUser();
        if ($member) {
            $member->AuthTokens()->removeAll();
        }

        Security::setCurrentUser(null);
    }
}
