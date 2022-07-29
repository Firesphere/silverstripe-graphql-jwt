<?php

declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Helpers;

use Firesphere\GraphQLJWT\Resolvers\Resolver;
use InvalidArgumentException;
use SilverStripe\Core\Extensible;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

/**
 * Generates / Validates a MemberTokenType for graphql responses
 *
 * @mixin Extensible
 */
trait CreateTokenResponseGenerator
{
    /**
     * Generate MemberToken response
     *
     * @param string $status Status code
     * @param Member $member
     * @param string $token
     * @return array Response in format required by MemberToken
     */
    protected static function generateCreateTokenResponse(ValidationResult $validationResult, Member $member = null, string $token = null): array
    {
        // Success response
        $valid = $validationResult->isValid();
        $status = $valid ? Resolver::STATUS_OK : Resolver::STATUS_BAD_LOGIN;
        $message = count($validationResult->getMessages()) > 0
            ? $validationResult->getMessages()[0]["message"]
            : ErrorMessageGenerator::getErrorMessage($status);

        $response = [
            'valid'   => $valid,
            'member'  => $valid && $member && $member->exists() ? $member : null,
            'token'   => $token,
            'status'  => $status,
            'code'    => $valid ? 200 : 401,
            'message' => $message,
        ];

        return $response;
    }
}
