<?php
/**
 * Created by PhpStorm.
 * User: simon
 * Date: 02-Dec-17
 * Time: 11:30
 */

namespace Firesphere\GraphQLJWT\Tests;

use Firesphere\GraphQLJWT\Helpers\SubjectData;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Convert;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;

class MemberExtensionTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected function setUp()
    {
        return parent::setUp();
    }

    public function testMemberExists()
    {
        $member = $this->objFromFixture(Member::class, 'admin');
        $data = $member->getJWTData();
        $result = Convert::json2obj($data);

        $this->assertEquals($member->ID, $result->id);
        $this->assertEquals($member->Email, $result->userName);
    }

    public function testExtraMemberData()
    {
        /** @var Member $member */
        $member = $this->objFromFixture(Member::class, 'admin');
        $member->FirstName = 'Test';
        $member->Surname = 'Member';
        Config::modify()->set(Member::class, 'jwt_subject_fields', ['FirstName', 'LastName']);

        $data = $member->getJWTData();
        $result = Convert::json2obj($data);

        $this->assertEquals('Test', $result->FirstName);
        $this->assertEquals('Member', $result->Surname);
    }

    public function testNoMember()
    {
        $data = Member::create()->getJWTData();
        $result = Convert::json2obj($data);

        $this->assertNull($result->id);
    }
}
