<?php

namespace Firesphere\GraphQLJWT\Tests;

use App\Users\GraphQL\Types\TokenStatusEnum;
use Exception;
use Firesphere\GraphQLJWT\Authentication\JWTAuthenticator;
use Firesphere\GraphQLJWT\Extensions\MemberExtension;
use Firesphere\GraphQLJWT\Mutations\CreateTokenMutationCreator;
use GraphQL\Type\Definition\ResolveInfo;
use SilverStripe\Control\Controller;
use SilverStripe\Core\Environment;
use SilverStripe\Dev\SapphireTest;
use SilverStripe\ORM\ValidationException;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

class JWTAuthenticatorTest extends SapphireTest
{
    protected static $fixture_file = '../fixtures/JWTAuthenticatorTest.yml';

    protected $member;

    protected $token;

    /**
     * @throws ValidationException
     */
    public function setUp()
    {
        Environment::setEnv('JWT_SIGNER_KEY', 'test_signer');

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

    /**
     * @throws Exception
     */
    public function testValidToken()
    {
        $authenticator = JWTAuthenticator::singleton();
        $request = clone Controller::curr()->getRequest();
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        $result = $authenticator->authenticate(['token' => $this->token], $request);

        $this->assertInstanceOf(Member::class, $result);
        $this->assertEquals($this->member->ID, $result->ID);
    }

    /**
     * @throws Exception
     */
    public function testInvalidToken()
    {
        Environment::setEnv('JWT_SIGNER_KEY', 'string');

        $authenticator = JWTAuthenticator::singleton();
        $request = clone Controller::curr()->getRequest();
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        $result = $authenticator->authenticate(['token' => $this->token], $request);

        $this->assertNotInstanceOf(Member::class, $result);
    }

    /**
     * @throws Exception
     */
    public function testInvalidUniqueID()
    {
        $authenticator = JWTAuthenticator::singleton();
        $request = clone Controller::curr()->getRequest();
        $request->addHeader('Authorization', 'Bearer ' . $this->token);

        // Invalidate the Unique ID by making it something arbitrarily wrong
        /** @var Member|MemberExtension $member */
        $member = Member::get()->filter(['Email' => 'admin@silverstripe.com'])->first();
        $member->DestroyAuthTokens();

        $validationResult = ValidationResult::create();
        $result = $authenticator->authenticate(['token' => $this->token], $request, $validationResult);
        $this->assertFalse($validationResult->isValid());
        $this->assertNotEmpty($validationResult->getMessages());
        $this->assertEquals('Invalid token provided', $validationResult->getMessages()[TokenStatusEnum::STATUS_INVALID]['message']);
        $this->assertNull($result);
    }

    /**
     * @throws Exception
     */
    public function testRSAKey()
    {
        $keys = realpath(__DIR__ . '/../keys');
        Environment::setEnv('JWT_SIGNER_KEY', "{$keys}/private.key");
        Environment::setEnv('JWT_PUBLIC_KEY', "{$keys}/public.pub");

        $createToken = CreateTokenMutationCreator::singleton();

        $response = $createToken->resolve(
            null,
            ['Email' => 'admin@silverstripe.com', 'Password' => 'error'],
            [],
            new ResolveInfo([])
        );

        $token = $response['Token'];

        $authenticator = JWTAuthenticator::singleton();
        $request = clone Controller::curr()->getRequest();
        $request->addHeader('Authorization', 'Bearer ' . $token);

        $result = $authenticator->authenticate(['token' => $token], $request);

        $this->assertInstanceOf(Member::class, $result);
        $this->assertEquals($this->member->ID, $result->ID);

        Environment::setEnv('JWT_SIGNER_KEY', 'test_signer');
        // After changing the key to a string, the token should be invalid
        $result = $authenticator->authenticate(['token' => $token], $request);
        $this->assertNull($result);
    }
}
