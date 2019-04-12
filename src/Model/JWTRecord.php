<?php

namespace Firesphere\GraphQLJWT\Model;

use SilverStripe\ORM\DataObject;
use SilverStripe\Security\Member;

/**
 * @property string $UID
 * @property string $UserAgent
 * @method Member Member()
 */
class JWTRecord extends DataObject
{
    private static $table_name = 'Firesphere_JWTRecord';

    private static $db = [
        'UID'       => 'Varchar(255)',
        'UserAgent' => 'Text',
    ];

    private static $has_one = [
        'Member' => Member::class,
    ];
}
