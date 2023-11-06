<?php declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Authentication;

use BadMethodCallException;
use Exception;
use Firesphere\GraphQLJWT\Extensions\MemberExtension;
use Firesphere\GraphQLJWT\Helpers\HeaderExtractor;
use OutOfBoundsException;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injectable;
use SilverStripe\Core\Injector\Injector;
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
    use Injectable;

    /**
     * @param HTTPRequest $request
     * @return null|Member
     * @throws OutOfBoundsException
     * @throws BadMethodCallException
     * @throws Exception
     */
    public function authenticateRequest(HTTPRequest $request): ?Member
    {
        // Check token
        $token = $this->getAuthorizationHeader($request);
        if (!$token) {
            return null;
        }

        // Validate the token. This is critical for security
        $member = Injector::inst()->get(JWTAuthenticator::class)
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
     * @param Member $member
     * @param bool $persistent
     * @param HTTPRequest|null $request
     */
    public function logIn(Member $member, $persistent = false, HTTPRequest $request = null): void
    {
        Security::setCurrentUser($member);
    }

    /**
     * @param HTTPRequest|null $request
     */
    public function logOut(HTTPRequest $request = null): void
    {
        // We don't take any action here.
        // If we delete all tokens in this section, when a user logs out using a web interface (i.e. CMS), all the tokens will become invalid.
    }
}
