<?php

namespace Firesphere\GraphQLJWT\Helpers;


use Firesphere\GraphQLJWT\Resolvers\Resolver;
use InvalidArgumentException;

trait RequestPasswordResetResponseGenerator
{

  private static function getMessage($status)
  {
    switch ($status) {
      case Resolver::STATUS_BAD_REQUEST:
        return _t('JWT.STATUS_BAD_REQUEST', 'Invalid request');
      case Resolver::STATUS_OK:
        return _t('JWT.REQUEST_PASSWORD_RESET_STATUS_OK', 'Password reset request sent');
      default:
        throw new InvalidArgumentException("Invalid status");
    }
  }

  public static function generateRequestPasswordResponse($status): array
  {
    return [
      'successful' => $status,
      'message' => self::getMessage($status)
    ];
  }
}
