<?php

namespace Firesphere\GraphQLJWT\Helpers;

use Firesphere\GraphQLJWT\Resolvers\Resolver;

trait MutationResultGenerator
{
  public static function generateResultResponse(string $result, array $messages = []): array
  {
    $messages = count($messages) ? $messages : [ErrorMessageGenerator::getResultMessage($result)];
    return [
      'result' => $result,
      'message' => $messages,
    ];
  }
}
