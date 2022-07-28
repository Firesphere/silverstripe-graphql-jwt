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

  public static function generateInvalidPasswordResponse($status, array $messages): array
  {

    $message = implode(", ", $messages);

    return [
      'successful' => $status,
      'message' => $message,
    ];
  }
}
