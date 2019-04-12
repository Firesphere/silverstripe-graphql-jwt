<?php

namespace Firesphere\GraphQLJWT\Helpers;

use App\Users\GraphQL\Types\TokenStatusEnum;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;
use InvalidArgumentException;
use Lcobucci\JWT\Token;
use SilverStripe\Control\HTTPResponse_Exception;
use SilverStripe\Security\Member;

/**
 * Generates / Validates a MemberTokenType for graphql responses
 */
trait GeneratesTokenOutput
{
    /**
     * Humanise error message based on status code
     *
     * @param string $status
     * @return string
     * @throws InvalidArgumentException
     */
    public function getErrorMessage($status)
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
     * @param string       $status Status code
     * @param Member       $member
     * @param string|Token $token
     * @return array Response in format required by MemberToken
     * @throws HTTPResponse_Exception
     */
    protected function generateResponse($status, $member = null, $token = null)
    {
        // Success response
        if ($status == TokenStatusEnum::STATUS_OK) {
            return [
                'Valid'  => true,
                'Member' => $member && $member->exists() ? $member : null,
                'Token'  => (string)$token,
                'Status' => $status,
                'Code'   => 200,
            ];
        }

        // Note: Use 426 to denote "please renew me" as a response code
        $code = $status === TokenStatusEnum::STATUS_EXPIRED ? 426 : 401;

        // Check if errors should use http errors
        if (JWTAuthenticator::config()->get('prefer_http_errors')) {
            $message = $this->getErrorMessage($status);
            throw new HTTPResponse_Exception($message, $code);
        }

        // JSON error instead
        return [
            'Valid'  => false,
            'Member' => null,
            'Token'  => $token ? (string)$token : null,
            'Status' => $status,
            'Code'   => $code,
        ];
    }
}
