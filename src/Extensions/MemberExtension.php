<?php

namespace Firesphere\GraphQLJWT\Extensions;

use SilverStripe\Forms\CheckboxField;
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
        if ($this->owner->JWTUniqueID) {
            $fields->addFieldsToTab(
                'Root.Main',
                [
                    CheckboxField::create('reset', 'Reset the Token ID to disable this user\'s remote login')
                ]
            );
        }
    }

    public function onBeforeWrite()
    {
        parent::onBeforeWrite();
        if ($this->owner->reset) {
            $this->owner->JWTUniqueID = null;
        }
    }
}
