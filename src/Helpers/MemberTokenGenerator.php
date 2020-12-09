<?php declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Helpers;

use Firesphere\GraphQLJWT\Resolvers\Resolver;
use InvalidArgumentException;
use SilverStripe\Core\Extensible;
use SilverStripe\Security\Member;

/**
 * Generates / Validates a MemberTokenType for graphql responses
 *
 * @mixin Extensible
 */
trait MemberTokenGenerator
{
    /**
     * Humanise error message based on status code
     *
     * @param string $status
     * @return string
     * @throws InvalidArgumentException
     */
    public static function getErrorMessage(string $status): string
    {
        switch ($status) {
            case Resolver::STATUS_EXPIRED:
                return _t('JWT.STATUS_EXPIRED', 'Token is expired, please renew your token with a refreshToken query');
            case Resolver::STATUS_DEAD:
                return _t('JWT.STATUS_DEAD', 'Token is expired, but is too old to renew. Please log in again.');
            case Resolver::STATUS_INVALID:
                return _t('JWT.STATUS_INVALID', 'Invalid token provided');
            case Resolver::STATUS_BAD_LOGIN:
                return _t('JWT.STATUS_BAD_LOGIN', 'Sorry your email and password combination is rejected');
            case Resolver::STATUS_OK:
                return _t('JWT.STATUS_OK', 'Token is ok');
            default:
                throw new InvalidArgumentException("Invalid status");
        }
    }

    /**
     * Generate MemberToken response
     *
     * @param string $status Status code
     * @param Member $member
     * @param string $token
     * @return array Response in format required by MemberToken
     */
    protected static function generateResponse(string $status, Member $member = null, string $token = null): array
    {
        // Success response
        $valid = $status === Resolver::STATUS_OK;
        $response = [
            'valid'   => $valid,
            'member'  => $valid && $member && $member->exists() ? $member : null,
            'token'   => $token,
            'status'  => $status,
            'code'    => $valid ? 200 : 401,
            'message' => static::getErrorMessage($status),
        ];

        return $response;
    }
}
