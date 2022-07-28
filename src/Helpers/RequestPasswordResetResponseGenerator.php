<?php

namespace Firesphere\GraphQLJWT\Helpers;



trait RequestPasswordResetResponseGenerator
{

  public static function generateRequestPasswordResponse($status): array
  {
    return [
      'successful' => $status,
      'message' => ErrorMessageGenerator::getRequestResetPasswordMessage($status)
    ];
  }
}
