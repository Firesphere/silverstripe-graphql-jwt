<?php

namespace Firesphere\GraphQLJWT\Helpers;


trait MutationResultGenerator
{

  private static function getFirstMessage(array $messages)
  {
    return array_map(function ($message) {
      if (gettype($message) === "string") return $message;
      if (gettype($message) === "array" && isset($message['message'])) return $message['message'];
      return 'Something unexpected went wrong with your request, contact support to recieve help';
    }, $messages);
  }


  public static function generateResultResponse(string $result, array $messages = []): array
  {
    $messages = count($messages) ? self::getFirstMessage($messages) : [ErrorMessageGenerator::getResultMessage($result)];
    return [
      'result' => $result,
      'message' => $messages,
    ];
  }
}
