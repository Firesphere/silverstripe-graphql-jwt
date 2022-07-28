<?php


namespace Firesphere\GraphQLJWT\Resolvers;

use Firesphere\GraphQLJWT\Authentication\CustomAuthenticatorRegistry;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;
use Firesphere\GraphQLJWT\Extensions\MemberExtension;
use Firesphere\GraphQLJWT\Helpers\HeaderExtractor;
use Firesphere\GraphQLJWT\Helpers\MemberTokenGenerator;
use Firesphere\GraphQLJWT\Model\JWTRecord;
use GraphQL\Type\Definition\ResolveInfo;
use Psr\Container\NotFoundExceptionInterface;
use SilverStripe\Control\Controller;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Injector\Injector;
use OutOfBoundsException;
use BadMethodCallException;
use Exception;
use Firesphere\GraphQLJWT\Helpers\AnonymousTokenGenerator;
use Firesphere\GraphQLJWT\Helpers\RequestPasswordResetResponseGenerator;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Authenticator;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use Generator;

/**
 * @todo Enum types should allow mapping to these constants (see enums.yml, duplicate code)
 */
class Resolver
{
    use MemberTokenGenerator;
    use AnonymousTokenGenerator;
    use HeaderExtractor;
    use RequestPasswordResetResponseGenerator;

    /**
     * Valid token
     */
    const STATUS_OK = 'OK';

    /**
     * Not a valid token
     */
    const STATUS_INVALID = 'INVALID';

    /**
     * Expired but can be renewed
     */
    const STATUS_EXPIRED = 'EXPIRED';

    /**
     * Expired and cannot be renewed
     */
    const STATUS_DEAD = 'DEAD';

    /**
     * Provided user / password were incorrect
     */
    const STATUS_BAD_LOGIN = 'BAD_LOGIN';


    /**
     * @return mixed
     * @throws \Exception
     */
    public static function resolveValidateToken()
    {
        /** @var JWTAuthenticator $authenticator */
        $authenticator = Injector::inst()->get(JWTAuthenticator::class);
        $request = Controller::curr()->getRequest();
        $token = static::getAuthorizationHeader($request);

        /** @var JWTRecord $record */
        list($record, $status) = $authenticator->validateToken($token, $request);
        $member = $status === self::STATUS_OK ? $record->Member() : null;
        return static::generateResponse($status, $member, $token);
    }

    /**
     * @return array
     * @throws NotFoundExceptionInterface
     * @throws BadMethodCallException
     * @throws OutOfBoundsException
     * @throws Exception
     */
    public static function resolveRefreshToken(): array
    {
        $authenticator = Injector::inst()->get(JWTAuthenticator::class);
        $request = Controller::curr()->getRequest();
        $token = static::getAuthorizationHeader($request);

        // Check status of existing token
        /** @var JWTRecord $record */
        list($record, $status) = $authenticator->validateToken($token, $request);
        $member = null;
        switch ($status) {
            case self::STATUS_OK:
            case self::STATUS_EXPIRED:
                $member = $record->Member();
                $renewable = true;
                break;
            case self::STATUS_DEAD:
            case self::STATUS_INVALID:
            default:
                $member = null;
                $renewable = false;
                break;
        }

        // Check if renewable
        if (!$renewable) {
            return static::generateResponse($status);
        }

        // Create new token for member
        $newToken = $authenticator->generateToken($request, $member);
        return static::generateResponse(self::STATUS_OK, $member, $newToken->toString());
    }


    /**
     * @param mixed $object
     * @param array $args
     * @return array
     * @throws NotFoundExceptionInterface
     */
    public static function resolveCreateToken($object, array $args): array
    {
        // Authenticate this member
        $request = Controller::curr()->getRequest();
        $member = static::getAuthenticatedMember($args, $request);

        // Handle unauthenticated
        if (!$member) {
            return static::generateResponse(self::STATUS_BAD_LOGIN);
        }

        // Create new token from this member
        $authenticator = Injector::inst()->get(JWTAuthenticator::class);
        $token = $authenticator->generateToken($request, $member);
        return static::generateResponse(self::STATUS_OK, $member, $token->toString());
    }

    public static function resolveLogOut($object, array $args): array
    {
        /** @var JWTAuthenticator $authenticator */
        $authenticator = Injector::inst()->get(JWTAuthenticator::class);
        $request = Controller::curr()->getRequest();
        $token = static::getAuthorizationHeader($request);

        /** @var JWTRecord $record */
        list($record, $status) = $authenticator->validateToken($token, $request);
        $member = $status === self::STATUS_OK ? $record->Member() : null;
        if (!$member) {
            return static::generateResponse($status, $member, $token);
        } else {
            $record->delete();
            return static::generateResponse(self::STATUS_DEAD, $member, $token);
        }
    }

    /**
     * Get any authenticator we should use for logging in users
     *
     * @return Authenticator[]|Generator
     */
    protected static function getLoginAuthenticators(): Generator
    {
        // Check injected authenticators
        yield from CustomAuthenticatorRegistry::singleton()->getCustomAuthenticators();

        // Get other login handlers from Security
        $security = Security::singleton();
        yield from $security->getApplicableAuthenticators(Authenticator::LOGIN);
    }

    /**
     * Get an authenticated member from the given request
     *
     * @param array $args
     * @param HTTPRequest $request
     * @return Member|MemberExtension
     */
    protected static function getAuthenticatedMember(array $args, HTTPRequest $request): ?Member
    {
        // Normalise the casing for the authenticator
        $data = [
            'Email' => $args['email'],
            'Password' => $args['password'] ?? null,
        ];
        // Login with authenticators
        foreach (static::getLoginAuthenticators() as $authenticator) {
            $result = ValidationResult::create();
            $member = $authenticator->authenticate($data, $request, $result);
            if ($member && $result->isValid()) {
                return $member;
            }
        }

        return null;
    }
}
