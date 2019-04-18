<?php

namespace Firesphere\GraphQLJWT\Tests;

use App\Users\GraphQL\Types\TokenStatusEnum;
use Exception;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;
use Firesphere\GraphQLJWT\Mutations\CreateTokenMutationCreator;
use Firesphere\GraphQLJWT\Queries\ValidateTokenQueryCreator;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Session;
use SilverStripe\Core\Config\Config;
use SilverStripe\Core\Environment;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationException;
use SilverStripe\Security\Member;

class ValidateTokenQueryCreatorTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected $member;

    protected $token;

    /**
     * @throws ValidationException
     */
    public function setUp()
    {
        Environment::putEnv('JWT_SIGNER_KEY=test_signer');

        parent::setUp();
        $this->member = $this->objFromFixture(Member::class, 'admin');
        $createToken = CreateTokenMutationCreator::singleton();

        $response = $createToken->resolve(
            null,
            ['Email' => 'admin@silverstripe.com', 'Password' => 'error'],
            [],
            new ResolveInfo([])
        );

        $this->token = $response['Token'];
    }

    public function tearDown()
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

        $queryCreator = ValidateTokenQueryCreator::singleton();
        $response = $queryCreator->resolve(null, [], [], new ResolveInfo([]));

        $this->assertTrue($response['Valid']);
    }

    /**
     * @throws ValidationException
     * @throws Exception
     */
    public function testExpiredToken()
    {
        Config::modify()->set(JWTAuthenticator::class, 'nbf_expiration', -5);

        $createToken = CreateTokenMutationCreator::singleton();

        $response = $createToken->resolve(
            null,
            ['Email' => 'admin@silverstripe.com', 'Password' => 'error'],
            [],
            new ResolveInfo([])
        );
        $this->token = $response['Token'];

        $this->buildRequest();

        $queryCreator = ValidateTokenQueryCreator::singleton();
        $response = $queryCreator->resolve(null, [], [], new ResolveInfo([]));

        $this->assertFalse($response['Valid']);
        $this->assertEquals(TokenStatusEnum::STATUS_EXPIRED, $response['Status']);
        $this->assertEquals(401, $response['Code']);
        $this->assertEquals('Token is expired, please renew your token with a refreshToken query', $response['Message']);
    }
}
