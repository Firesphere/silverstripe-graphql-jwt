<?php

namespace Firesphere\GraphQLJWT\Helpers;

use Firesphere\GraphQLJWT\Resolvers\Resolver;

trait MutationResultGenerator
{
  public static function generateResultResponse(string $result, array $messages = []): array
  {
    $messages = [...$messages, ErrorMessageGenerator::getResultMessage($result)];
    return [
      'result' => $result,
      'message' => ErrorMessageGenerator::getResultMessage($result),
    ];
  }
}
