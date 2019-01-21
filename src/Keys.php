<?php
/**
 * Created by PhpStorm.
 * User: bogdans
 * Date: 1/21/2019
 * Time: 11:41 AM
 */

namespace Encryption;

use Encryption\EncryptionErrorHandler;

/**
 * Class Keys
 * @package Encryption
 */
class Keys
{

	/**
	 * @return string
	 */
	public function GenerateBoxKey(): string
	{
		if( !function_exists('sodium_crypto_box_keypair') ) {
			throw new EncryptionErrorHandler('sodium_crypto_box_keypair');
		}

		return sodium_crypto_box_keypair();
	}


	/**
	 * @return string
	 */
	public function GenerateSignKey(): string
	{
		if( !function_exists('sodium_crypto_sign_keypair') ) {
			throw new EncryptionErrorHandler('sodium_crypto_sign_keypair');
		}

		return sodium_crypto_sign_keypair();
	}


	/**
	 * @param string $boxKey
	 * @return array
	 */
	public function SplitBoxKey(string $boxKey): array
	{

		if( !function_exists('sodium_crypto_box_secretkey') || !function_exists('sodium_crypto_box_publickey') ) {
			throw new EncryptionErrorHandler('sodium_crypto_box_secretkey && sodium_crypto_box_publickey');
		}

		return [
			'public' => sodium_crypto_box_publickey($boxKey),
			'secret' => sodium_crypto_box_secretkey($boxKey)
		];

	}


	/**
	 * @param string $splitKey
	 * @return array
	 */
	public function SplitSignKey(string $splitKey): array
	{
		if( !function_exists('sodium_crypto_sign_secretkey') || !function_exists('sodium_crypto_sign_publickey') ) {
			throw new EncryptionErrorHandler('sodium_crypto_sign_secretkey && sodium_crypto_sign_publickey');
		}

		return [
			'public' => sodium_crypto_sign_publickey($splitKey),
			'secret' => sodium_crypto_sign_secretkey($splitKey)
		];
	}


	/**
	 * @param $secretKey
	 * @param $publicKey
	 * @return string
	 */
	public function GeneratePublicSecretKeyPair($secretKey, $publicKey): string
	{
		if( !function_exists('sodium_crypto_box_keypair_from_secretkey_and_publickey') ) {
			throw new EncryptionErrorHandler('sodium_crypto_box_keypair_from_secretkey_and_publickey');
		}

		return sodium_crypto_box_keypair_from_secretkey_and_publickey($secretKey, $publicKey);
	}

}