<?php

namespace Firesphere\GraphQLJWT\Helpers;

use Firesphere\GraphQLJWT\Resolvers\Resolver;
use InvalidArgumentException;


/**
 * Generates Error messages for responses
 *
 * @mixin Extensible
 */
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
      case Resolver::STATUS_BAD_REQUEST:
        return _t('JWT.STATUS_BAD_REQUEST', 'Invalid request');
      case Resolver::STATUS_OK:
        return _t('JWT.STATUS_OK', 'Token is ok');
      default:
        throw new InvalidArgumentException("Invalid status");
    }
  }

  public static function getResetPasswordMessage(string $status): string
  {
    switch ($status) {
      case Resolver::STATUS_EXPIRED:
        return _t('JWT.STATUS_EXPIRED', 'Token is expired, please renew your token with a refreshToken query');
      case Resolver::STATUS_DEAD:
        return _t('JWT.STATUS_DEAD', 'Token is expired, but is too old to renew. Please log in again.');
      case Resolver::STATUS_INVALID:
        return _t('JWT.STATUS_INVALID', 'Invalid token provided');
      case Resolver::STATUS_BAD_REQUEST:
        return _t('JWT.STATUS_BAD_REQUEST', 'Invalid request');
      case Resolver::STATUS_OK:
        return _t('JWT.STATUS_OK', 'Password is reset');
      default:
        throw new InvalidArgumentException("Invalid status");
    }
  }

  public static function getRequestResetPasswordMessage($status)
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
}
