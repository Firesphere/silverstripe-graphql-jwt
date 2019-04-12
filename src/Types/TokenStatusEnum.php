<?php

namespace App\Users\GraphQL\Types;

use GraphQL\Type\Definition\EnumType;

class TokenStatusEnum extends EnumType
{
    /**
     * Valid token
     */
    const STATUS_OK = 'OK';

    /**
     * Not a valid token
     */
    const STATUS_INVALID = 'INVALID';

    /**
     * Expired but can be renewed
     */
    const STATUS_EXPIRED = 'EXPIRED';

    /**
     * Expired and cannot be renewed
     */
    const STATUS_DEAD = 'DEAD';

    /**
     * Provided user / password were incorrect
     */
    const STATUS_BAD_LOGIN = 'BAD_LOGIN';

    public function __construct()
    {
        $values = [
            self::STATUS_OK        => [
                'value'       => self::STATUS_OK,
                'description' => 'JWT token is valid',
            ],
            self::STATUS_INVALID   => [
                'value'       => self::STATUS_INVALID,
                'description' => 'JWT token is not valid',
            ],
            self::STATUS_EXPIRED   => [
                'value'       => self::STATUS_EXPIRED,
                'description' => 'JWT token has expired, but can be renewed',
            ],
            self::STATUS_DEAD      => [
                'value'       => self::STATUS_DEAD,
                'description' => 'JWT token has expired and cannot be renewed',
            ],
            self::STATUS_BAD_LOGIN => [
                'value'       => self::STATUS_BAD_LOGIN,
                'description' => 'JWT token could not be created due to invalid login credentials',
            ],
        ];
        $config = [
            'name'        => 'TokenStatus',
            'description' => 'Status of token',
            'values'      => $values,
        ];

        parent::__construct($config);
    }

    /**
     * Safely create a single type creator only
     *
     * @return TokenStatusEnum
     */
    public static function instance()
    {
        static $instance = null;
        if (!$instance) {
            $instance = new self();
        }
        return $instance;
    }
}
