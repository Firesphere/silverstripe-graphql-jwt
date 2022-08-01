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
      case Resolver::STATUS_OK:
        return _t('JWT.STATUS_OK', 'Token is ok');
      default:
        throw new InvalidArgumentException("Invalid status");
    }
  }

  public static function getResultMessage($result){
    switch($result){
      case Resolver::RESULT_ALREADY_REGISTERED:
        return _t('JWT.RESULT_ALREADY_REGISTERED', 'Email address is already registered');
      case Resolver::RESULT_PASSWORD_MISSMATCH:
        return _t('JWT.RESULT_PASSWORD_MISSMATCH', 'Passwords do not match');
      case Resolver::RESULT_BAD_LOGIN:
        return _t('JWT.RESULT_BAD_LOGIN', 'Email address or password is incorrect');
      case Resolver::RESULT_BAD_REQUEST:
        return _t('JWT.RESULT_BAD_REQUEST', 'Something went wrong, please try again later.');
      case Resolver::RESULT_OK:
        return _t('JWT.RESULT_OK', 'Success');
      default:
        throw new InvalidArgumentException("Invalid result");
    }
  }
}
