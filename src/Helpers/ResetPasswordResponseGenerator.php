<?php

namespace Firesphere\GraphQLJWT\Helpers;

trait ResetPasswordResponseGenerator
{
  public static function generateResetPasswordResponse($status): array
  {
    return [
      'successful' => $status,
      'message' => ErrorMessageGenerator::getResetPasswordMessage($status)
    ];
  }
}
