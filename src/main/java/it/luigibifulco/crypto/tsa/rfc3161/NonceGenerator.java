package it.luigibifulco.crypto.tsa.rfc3161;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import it.luigibifulco.crypto.tsa.rfc3161.exceptions.ClientException;

/**
 * 
 * @author Luigi Bifulco
 *
 */
public final class NonceGenerator {

	public static final BigInteger generateNonce() {
		try {
			final SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			return new BigInteger(64, random);
		} catch (final NoSuchAlgorithmException exception) {
			throw new ClientException("Failed to initialize SecureRandom instance", exception);
		}
	}
}
