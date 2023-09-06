<?php

namespace Firesphere\GraphQLJWT\Tests;

use Exception;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;
use Firesphere\GraphQLJWT\Resolvers\Resolver;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Member;

class ValidateTokenTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected $member;

    protected $token;

    protected function setUp(): void
    {
        Controller::curr()->getRequest()->addHeader('Origin', 'GraphQLJWT_Test');
        Environment::putEnv('JWT_SIGNER_KEY=a_256bits_test_signer_or_it_would_not_work_correctly');

        parent::setUp();
        $this->member = $this->objFromFixture(Member::class, 'admin');
        $response = Resolver::resolveCreateToken(
            null,
            ['email' => 'admin@silverstripe.com', 'password' => 'error']
        );

        $this->token = $response['token'];
    }

    protected function tearDown(): void
    {
        parent::tearDown();
    }

    private function buildRequest()
    {
        $request = clone Controller::curr()->getRequest();
        $request->addHeader('Authorization', 'Bearer ' . $this->token);
        $request->setSession(new Session(['hello' => 'bye'])); // We need a session
        Controller::curr()->setRequest($request);

        return $request;
    }

    /**
     * @throws Exception
     */
    public function testValidateToken()
    {
        $this->buildRequest();

        $response = Resolver::resolveValidateToken();

        $this->assertTrue($response['valid']);
    }

    /**
     * @throws Exception
     */
    public function testExpiredToken()
    {
        Config::modify()->set(JWTAuthenticator::class, 'nbf_expiration', -5);

        $response = Resolver::resolveCreateToken(
            null,
            ['email' => 'admin@silverstripe.com', 'password' => 'error']
        );
        $this->token = $response['token'];

        $this->buildRequest();

        $response = Resolver::resolveValidateToken();

        $this->assertFalse($response['valid']);
        $this->assertEquals(Resolver::STATUS_EXPIRED, $response['status']);
        $this->assertEquals(401, $response['code']);
        $this->assertEquals(
            'Token is expired, please renew your token with a refreshToken query',
            $response['message']
        );
    }
}
