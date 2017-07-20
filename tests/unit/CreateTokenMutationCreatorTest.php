<?php

namespace Firesphere\GraphQLJWT\Tests;

use Firesphere\GraphQLJWT\CreateTokenMutationCreator;
use Firesphere\GraphQLJWT\JWTAuthenticator;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;

class CreateTokenMutationCreatorTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected $member;

    public function setUp()
    {
        parent::setUp();
        $this->member = $this->objFromFixture(Member::class, 'admin');
    }

    public function tearDown()
    {
        parent::tearDown();
    }

    public function testResolveValid()
    {
        $createToken = Injector::inst()->get(CreateTokenMutationCreator::class);

        $response = $createToken->resolve(null, ['Email' => 'admin@silverstripe.com', 'Password' => 'error'], [], new ResolveInfo([]));

        $this->assertTrue($response instanceof Member);
        $this->assertNotNull($response->Token);
    }

    public function testResolveInvalidWithAllowedAnonymous()
    {
        $authenticator = Injector::inst()->get(CreateTokenMutationCreator::class);

        $response = $authenticator->resolve(null, ['Email' => 'admin@silverstripe.com', 'Password' => 'wrong'], [], new ResolveInfo([]));

        $this->assertTrue($response instanceof Member);
        $this->assertEquals(0, $response->ID);
        $this->assertNotNull($response->Token);
    }

    public function testResolveInvalidWithoutAllowedAnonymous()
    {
        Config::modify()->set(JWTAuthenticator::class, 'anonymous_allowed', false);
        $authenticator = Injector::inst()->get(CreateTokenMutationCreator::class);

        $response = $authenticator->resolve(null, ['Email' => 'admin@silverstripe.com', 'Password' => 'wrong'], [], new ResolveInfo([]));

        $this->assertTrue($response instanceof Member);
        $this->assertNull($response->Token);
    }
}
