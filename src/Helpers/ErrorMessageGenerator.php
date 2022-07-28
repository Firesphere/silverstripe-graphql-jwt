<?php

use Firesphere\GraphQLJWT\Resolvers\Resolver;

class ErrorMessageGenerator
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
}
