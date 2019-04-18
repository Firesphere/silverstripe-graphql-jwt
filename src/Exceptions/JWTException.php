<?php declare(strict_types=1);

class JWTException extends Exception
{
    public function __construct($message = 'JWT Exception', $code = 1, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
