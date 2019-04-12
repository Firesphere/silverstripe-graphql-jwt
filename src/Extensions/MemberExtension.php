<?php

namespace Firesphere\GraphQLJWT\Extensions;

use Firesphere\GraphQLJWT\Model\JWTRecord;
use SilverStripe\Core\Convert;
use SilverStripe\Forms\FieldList;
use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\HasManyList;
use SilverStripe\Security\Member;
use stdClass;

/**
 * Class MemberExtension
 * Add a unique token to the Member for extra validation
 *
 * @property $owner Member|self
 * @method HasManyList|JWTRecord[] AuthTokens()
 */
class MemberExtension extends DataExtension
{
    /**
     * List of names of extra subject fields to add to JWT token
     *
     * @config
     * @var array
     */
    private static $jwt_subject_fields = [];

    /**
     * @config
     * @var array
     */
    private static $has_many = [
        'AuthTokens' => JWTRecord::class,
    ];

    public function updateCMSFields(FieldList $fields)
    {
        $fields->removeByName('AuthTokens');
    }

    /**
     * Option to add data to the JWT Subject
     *
     * @return string
     */
    public function getJWTData()
    {
        $data = new stdClass();
        $identifier = Member::config()->get('unique_identifier_field');
        $extraFields = Member::config()->get('jwt_subject_fields');

        $data->type = 'member';
        $data->id = $this->owner->ID;
        $data->userName = $this->owner->$identifier;

        if (is_array($extraFields)) {
            foreach ($extraFields as $field) {
                $dataField = lcfirst($field);
                $data->$dataField = $this->owner->$field;
            }
        }

        return Convert::raw2json($data);
    }
}
