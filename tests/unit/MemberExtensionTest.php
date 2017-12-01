<?php
/**
 * Created by PhpStorm.
 * User: simon
 * Date: 02-Dec-17
 * Time: 11:30
 */

namespace Firesphere\GraphQLJWT\Tests;


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

    public function testNoMember()
    {
        $data = Member::create()->getJWTData();
        $result = Convert::json2obj($data);

        $this->assertInstanceOf(\stdClass::class, $result);

        $this->assertNull($result->id);
    }
}