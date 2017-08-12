<?php
namespace Firesphere\GraphQLJWT;


use SilverStripe\Forms\FieldList;
use SilverStripe\ORM\DataExtension;

/**
 * Class MemberExtension
 * Add a unique token to the Member for extra validation
 */
class MemberExtension extends DataExtension
{

    private static $db = [
        'JWTUniqueID' => 'Varchar(255)',
    ];

    private static $indexes = [
        'JWTUniqueID' => 'unique'
    ];

    public function updateCMSFields(FieldList $fields)
    {
        parent::updateCMSFields($fields);
        $fields->removeByName(['JWTUniqueID']);
    }
}