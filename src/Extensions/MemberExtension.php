<?php

namespace Firesphere\GraphQLJWT\Extensions;

use Firesphere\GraphQLJWT\Helpers\SubjectData;
use SilverStripe\Core\Convert;
use SilverStripe\Forms\CheckboxField;
use SilverStripe\Forms\FieldList;
use SilverStripe\ORM\DataExtension;
use SilverStripe\Security\Member;
use stdClass;

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

    /**
     * Option to add data to the JWT Subject
     *
     * @return string
     */
    public function getJWTData()
    {
        $data = new SubjectData();
        if ($this->owner->exists()) {
            $identifier = Member::config()->get('unique_identifier_field');
            $extraFields = Member::config()->get('jwt_subject_fields');
            $data->setId($this->owner->ID);
            $data->setUserName($this->owner->$identifier);
            if (is_array($extraFields)) {
                foreach ($extraFields as $field) {
                    $data->$field = $this->owner->$field;
                }
            }
        }

        return Convert::raw2json($data);
    }
}
