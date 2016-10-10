package it.luigibifulco.crypto.tsa.rfc3161;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;

import it.luigibifulco.crypto.tsa.rfc3161.config.Algorithm;
import it.luigibifulco.crypto.tsa.rfc3161.exceptions.DigestException;

/**
 * 
 * @author Luigi Bifulco
 *
 */
public class DigestGenerator {

	private static final int DEFAULT_BUFFER_SIZE = 1024 * 4;

	private final String m_filePath;

	private final Algorithm m_algorithm;

	private MessageDigest m_messageDigest;

	private byte[] m_digest = null;

	private File m_data;

	public DigestGenerator(final String p_filePath, final Algorithm p_algorithm) {
		m_algorithm = p_algorithm;
		m_filePath = p_filePath;
	}

	public byte[] digest() {
		if (m_digest == null) {
			m_digest = m_messageDigest.digest();
		}
		return m_digest;
	}

	public DigestGenerator generateDigest() {
		if (m_messageDigest == null || m_data == null) {
			throw new DigestException("Not initialised correctly");
		}

		InputStream input = null;

		try {
			input = new FileInputStream(m_data);
		} catch (final FileNotFoundException exception) {
			throw new DigestException("Failed to open input stream.", exception);
		}

		final byte[] buffer = new byte[DEFAULT_BUFFER_SIZE];
		int read = 0;
		try {
			while ((read = input.read(buffer)) != -1) {
				m_messageDigest.update(buffer, 0, read);
			}
		} catch (final IOException exception) {
			throw new DigestException("Failed to read file", exception);
		}

		try {
			input.close();
		} catch (final IOException exception) {
			throw new DigestException("Failed to close input stream", exception);
		}

		return this;
	}

	public DigestGenerator initDigest() {
		try {
			m_messageDigest = MessageDigest.getInstance(m_algorithm.getDigestAlgorithm());
		} catch (final NoSuchAlgorithmException exception) {
			throw new DigestException("Failed to get algorithm instance for " + m_algorithm.getDigestAlgorithm(),
					exception);
		}
		return this;
	}

	public DigestGenerator initFile() {
		m_data = new File(m_filePath);
		if (!m_data.exists() || !m_data.isFile() || !m_data.canRead()) {
			throw new DigestException("File does not exist, is not a file, or is not readable");
		}
		return this;
	}

	public DigestGenerator storeDigest(final String p_digestFile) {
		if (m_digest == null) {
			m_digest = m_messageDigest.digest();
		}
		final File digestFile = new File(p_digestFile);

		try {
			final OutputStream output = new FileOutputStream(digestFile);
			IOUtils.write(String.format("%s  %s", new String(Hex.encodeHex(m_digest)), m_data.getName()), output);
			output.close();
		} catch (final IOException exception) {
			throw new DigestException("Failed to save digest to file: " + digestFile.getName(), exception);
		}

		return this;
	}
}
