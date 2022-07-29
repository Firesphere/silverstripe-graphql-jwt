<?php

declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Model;

use SilverStripe\ORM\DataObject;
use SilverStripe\ORM\FieldType\DBIndexable;
use SilverStripe\Security\Member;

/**
 * @property string $UID
 * @property string $UserAgent
 * @method Member Member()
 */
class JWTRecord extends DataObject
{

    const TYPE_AUTH = 'auth';

    const TYPE_ANONYMOUS = 'anonymous';

    private static $table_name = 'JWTRecord';

    private static $db = [
        'UID'       => 'Varchar(255)',
        'UserAgent' => 'Text',
        'Type' => 'Varchar(255)',
    ];

    private static $has_one = [
        'Member' => Member::class,
    ];

    private static $indexes = [
        'UID' => [
            'type'    => DBIndexable::TYPE_UNIQUE,
            'columns' => ['UID'],
        ],
    ];
}
