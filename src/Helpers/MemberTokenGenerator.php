<?php declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Helpers;

use App\Users\GraphQL\Types\TokenStatusEnum;
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
    public function getErrorMessage(string $status): string
    {
        switch ($status) {
            case TokenStatusEnum::STATUS_EXPIRED:
                return _t('JWT.STATUS_EXPIRED', 'Token is expired, please renew your token with a refreshToken query');
            case TokenStatusEnum::STATUS_DEAD:
                return _t('JWT.STATUS_DEAD', 'Token is expired, but is too old to renew. Please log in again.');
            case TokenStatusEnum::STATUS_INVALID:
                return _t('JWT.STATUS_INVALID', 'Invalid token provided');
            case TokenStatusEnum::STATUS_BAD_LOGIN:
                return _t('JWT.STATUS_BAD_LOGIN', 'Sorry your email and password combination is rejected');
            case TokenStatusEnum::STATUS_OK:
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
    protected function generateResponse(string $status, Member $member = null, string $token = null): array
    {
        // Success response
        $valid = $status === TokenStatusEnum::STATUS_OK;
        $response = [
            'Valid'   => $valid,
            'Member'  => $valid && $member && $member->exists() ? $member : null,
            'Token'   => $token,
            'Status'  => $status,
            'Code'    => $valid ? 200 : 401,
            'Message' => $this->getErrorMessage($status),
        ];

        $this->extend('updateMemberToken', $response);
        return $response;
    }
}
