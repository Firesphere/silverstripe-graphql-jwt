<?php

namespace Firesphere\GraphQLJWT\tests;

use Firesphere\GraphQLJWT\CreateTokenMutationCreator;
use Firesphere\GraphQLJWT\JWTAuthenticator;
use GraphQL\Type\Definition\ResolveInfo;
use JWTException;
use SilverStripe\Control\Director;
use SilverStripe\Control\HTTPRequest;
use SilverStripe\Core\Environment;
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
        Environment::putEnv('JWT_SIGNER_KEY=test_signer');

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

        $this->assertInstanceOf(Member::class, $result);
        $this->assertEquals($this->member->ID, $result->ID);
    }

    public function testInvalidToken()
    {
        Environment::putEnv('JWT_SIGNER_KEY=string');

        $authenticator = Injector::inst()->get(JWTAuthenticator::class);
        $request = new HTTPRequest('POST', Director::absoluteBaseURL() . '/graphql');
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        $result = $authenticator->authenticate(['token' => $this->token], $request);

        $this->assertNotInstanceOf(Member::class, $result);

        Environment::putEnv('JWT_SIGNER_KEY=test_signer');
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

    public function testRSAKey()
    {
        Environment::putEnv('JWT_SIGNER_KEY=graphql-jwt/tests/keys/private.key');
        Environment::putEnv('JWT_PUBLIC_KEY=graphql-jwt/tests/keys/public.pub');

        $createToken = Injector::inst()->get(CreateTokenMutationCreator::class);

        $response = $createToken->resolve(
            null,
            ['Email' => 'admin@silverstripe.com', 'Password' => 'error'],
            [],
            new ResolveInfo([])
        );

        $token = $response->Token;

        $authenticator = Injector::inst()->get(JWTAuthenticator::class);
        $request = new HTTPRequest('POST', Director::absoluteBaseURL() . '/graphql');
        $request->addHeader('Authorization', 'Bearer ' . $token);

        $result = $authenticator->authenticate(['token' => $token], $request);

        $this->assertInstanceOf(Member::class, $result);
        $this->assertEquals($this->member->ID, $result->ID);

        Environment::putEnv('JWT_SIGNER_KEY=test_signer');
        // After changing the key to a string, the token should be invalid
        $result = $authenticator->authenticate(['token' => $token], $request);
        $this->assertNull($result);
    }
}
