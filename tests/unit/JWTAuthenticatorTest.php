<?php

namespace Firesphere\GraphQLJWT\tests;

use Firesphere\GraphQLJWT\CreateTokenMutationCreator;
use Firesphere\GraphQLJWT\JWTAuthenticator;
use GraphQL\Type\Definition\ResolveInfo;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Token;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;

class JWTAuthenticatorTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected $member;

    protected $token;

    public function setUp()
    {
        parent::setUp();
        $this->member = $this->objFromFixture(Member::class, 'admin');
        $createToken = Injector::inst()->get(CreateTokenMutationCreator::class);

        $response = $createToken->resolve(
            null,
            ['Email' => 'admin@silverstripe.com', 'Password' => 'error'],
            [],
            new ResolveInfo([])
        );

        $this->token = $response->Token;
    }

    public function tearDown()
    {
        parent::tearDown();
    }

    public function testValidToken()
    {
        $authenticator = Injector::inst()->get(JWTAuthenticator::class);
        $request = new HTTPRequest('POST', Director::absoluteBaseURL() . '/graphql');
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        $result = $authenticator->authenticate(['token' => $this->token], $request);

        $this->assertTrue($result instanceof Member);
        $this->assertEquals($this->member->ID, $result->ID);
    }

    public function testInvalidUniqueID()
    {
        $authenticator = Injector::inst()->get(JWTAuthenticator::class);
        $request = new HTTPRequest('POST', Director::absoluteBaseURL() . '/graphql');
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        // Invalidate the Unique ID by making it something arbitrarily wrong
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $member->JWTUniqueID = 'make_error';
        $member->write();

        $result = $authenticator->authenticate(['token' => $this->token], $request);

        $this->assertNull($result);
    }
}
