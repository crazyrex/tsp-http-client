package it.luigibifulco.crypto.tsa.rfc3161.config;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TSPAlgorithms;

/**
 * 
 * @author Luigi Bifulco
 *
 */
public enum Algorithm {
	MD5(TSPAlgorithms.MD5, "MD5"), SHA1(TSPAlgorithms.SHA1, "SHA1"), SHA256(TSPAlgorithms.SHA256,
			"SHA-256"), SHA384(TSPAlgorithms.SHA384, "SHA-384"), SHA512(TSPAlgorithms.SHA512, "SHA-512");

	private final ASN1ObjectIdentifier m_tspAlgorithm;

	private final String m_digestAlgorithm;

	private Algorithm(final ASN1ObjectIdentifier p_tspAlgorithm, final String p_digestAlgorithm) {
		m_tspAlgorithm = p_tspAlgorithm;
		m_digestAlgorithm = p_digestAlgorithm;
	}

	public String getDigestAlgorithm() {
		return m_digestAlgorithm;
	}

	public ASN1ObjectIdentifier getTspAlgorithm() {
		return m_tspAlgorithm;
	}

	public static final String hashAlgorithmForASN1ObjectIdentifier(final ASN1ObjectIdentifier p_asn1ObjectIdentifier) {
		for (final Algorithm alg : Algorithm.values()) {
			if (alg.getTspAlgorithm().equals(p_asn1ObjectIdentifier)) {
				return alg.name();
			}
		}
		return null;
	}

	public static final String hashAlgorithmForASN1ObjectIdentifier(final String p_asn1ObjectIdentifier) {
		final ASN1ObjectIdentifier objectIdentifier = new ASN1ObjectIdentifier(p_asn1ObjectIdentifier);

		for (final Algorithm alg : Algorithm.values()) {
			if (alg.getTspAlgorithm().equals(objectIdentifier)) {
				return alg.name();
			}
		}
		return null;
	}

}
