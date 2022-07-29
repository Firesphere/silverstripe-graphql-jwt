<?php

declare(strict_types=1);

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
            'message' => ErrorMessageGenerator::getErrorMessage($status),
        ];

        return $response;
    }
}
