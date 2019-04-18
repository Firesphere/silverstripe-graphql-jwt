<?php
/**
 * Created by PhpStorm.
 * User: simon
 * Date: 02-Dec-17
 * Time: 11:30
 */

namespace Firesphere\GraphQLJWT\Tests;

use Firesphere\GraphQLJWT\Extensions\MemberExtension;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Convert;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;

class MemberExtensionTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    public function testMemberExists()
    {
        /** @var Member|MemberExtension $member */
        $member = $this->objFromFixture(Member::class, 'admin');

        $data = $member->getJWTData();
        $result = Convert::json2obj($data);

        $this->assertEquals($member->Email, $result->userName);
    }

    public function testExtraMemberData()
    {
        /** @var Member|MemberExtension $member */
        $member = $this->objFromFixture(Member::class, 'admin');
        $member->Surname = 'Member';
        Config::modify()->set(Member::class, 'jwt_subject_fields', ['FirstName', 'Surname']);

        $data = $member->getJWTData();
        $result = Convert::json2obj($data);

        $this->assertEquals('Admin', $result->firstName);
        $this->assertEquals('Member', $result->surname);
    }

    public function testNoMember()
    {
        /** @var Member|MemberExtension $memberl */
        $memberl = Member::create();
        $data = $memberl->getJWTData();
        $result = Convert::json2array($data);

        $this->assertEquals(0, $result['id']);
    }
}
