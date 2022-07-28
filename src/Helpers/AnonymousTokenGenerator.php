<?php

namespace Firesphere\GraphQLJWT\Helpers;

use Firesphere\GraphQLJWT\Resolvers\Resolver;


/**
 * Validates an AnonymousToken for graphql responses
 *
 * @mixin Extensible
 */
trait AnonymousTokenGenerator
{
  /**
   * Generate MemberToken response
   *
   * @param string $status Status code
   * @param Member $member
   * @param string $token
   * @return array Response in format required by MemberToken
   */
  protected static function generateAnonymousResponse(string $status, string $token = null): array
  {
    // Success response
    $valid = $status === Resolver::STATUS_OK;
    $response = [
      'valid'   => $valid,
      'token'   => $token,
      'status'  => $status,
      'code'    => $valid ? 200 : 401,
      'message' => ErrorMessageGenerator::getErrorMessage($status),
    ];

    return $response;
  }
}
