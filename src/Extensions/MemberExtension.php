<?php

declare(strict_types=1);

namespace Firesphere\GraphQLJWT\Extensions;

use Firesphere\GraphQLJWT\Model\JWTRecord;
use SilverStripe\Forms\FieldList;
use SilverStripe\ORM\DataExtension;
use SilverStripe\ORM\HasManyList;
use SilverStripe\Security\Member;
use stdClass;

/**
 * Class MemberExtension
 * Add a unique token to the Member for extra validation
 *
 * @property Member|MemberExtension $owner
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

    private static $db = [
        'isActivated' => 'Boolean',
    ];

    private static $has_one = [
        'ResetToken' => JWTRecord::class,
        'SignupToken' => JWTRecord::class,
    ];

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
        $fields->removeByName('ResetToken');
        $fields->removeByName('SignupToken');
    }

    /**
     * Option to add data to the JWT Subject
     *
     * @return string
     */
    public function getJWTData(): string
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

        return json_encode($data);
    }

    /**
     * Destroy all JWT tokens
     *
     * @return Member
     */
    public function destroyAuthTokens(): Member
    {
        foreach ($this->owner->AuthTokens() as $token) {
            $token->delete();
        }
        return $this->owner;
    }

    public function Activate(){
        $this->owner->isActivated = true;
        $this->owner->SignupTokenID = null;
        $this->owner->write();
    }

    public function deActivate(){
        $this->owner->isActivated = false;
        $this->owner->write();
    }
}
