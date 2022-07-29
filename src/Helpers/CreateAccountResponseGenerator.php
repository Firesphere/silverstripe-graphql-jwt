<?php

namespace Firesphere\GraphQLJWT\Helpers;

use Firesphere\GraphQLJWT\Resolvers\Resolver;

trait CreateAccountResponseGenerator{
    public static function generateCreateAccountResponse(string $status, array $messages = []): array{
        $message = implode(", ", $messages);
        return [
            'successful' => $status === Resolver::STATUS_OK,
            'message' => ErrorMessageGenerator::getErrorMessage($status),
            'clientMessages' => $message,
        ];
    }
}