package it.luigibifulco.crypto.tsa.rfc3161;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.DefaultHttpClient;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.encoders.Base64;

import it.luigibifulco.crypto.tsa.rfc3161.exceptions.ClientException;

/**
 * 
 * @author Luigi Bifulco
 *
 */
public class HttpTimestampClient {

	private final HttpPost m_post;

	private final TimeStampRequest m_request;

	private StatusLine m_statusLine;

	private ByteArrayInputStream m_responseContent;

	private TimeStampResponse m_response;

	public HttpTimestampClient(final String p_url, String user, String password,
			final TimeStampRequest p_timeStampRequest) {
		m_post = new HttpPost(p_url);
		m_post.addHeader("User-Agent", "CROZ TSA Client");
		String userPassword = user + ":" + password;
		String auth = "Basic " + new String(Base64.encode(userPassword.getBytes()));
		m_post.addHeader("Authorization", auth);
		// m_post.addHeader("Content-Transfer-Encoding", "base64");

		m_request = p_timeStampRequest;
	}

	public HttpTimestampClient basicAuth(final String p_username, final String p_password) {
		throw new UnsupportedOperationException("Not implemented");
	}

	public HttpTimestampClient execute() {
		final DefaultHttpClient client = new DefaultHttpClient();
		try {
			final HttpResponse httpResponse = client.execute(m_post);
			m_statusLine = httpResponse.getStatusLine();

			m_responseContent = new ByteArrayInputStream(IOUtils.toByteArray(httpResponse.getEntity().getContent()));
		} catch (final IOException exception) {
			throw new ClientException("Failed to get response from server", exception);
		} finally {
			m_post.releaseConnection();
		}
		return this;
	}

	public int httpStatus() {
		return m_statusLine.getStatusCode();
	}

	public HttpTimestampClient initClient() {
		final ContentType contentType = ContentType.create("application/timestamp-query");

		try {
			final HttpEntity entity = new ByteArrayEntity(m_request.getEncoded(), contentType);
			// final HttpEntity entity = new StringEntity(new
			// Strm_request.getEncoded())), contentType);

			m_post.setEntity(entity);
		} catch (final IOException exception) {
			throw new ClientException("Failed to create post entity", exception);
		}

		return this;
	}

	public TimeStampResponse timestampResponse() {
		try {
			if (m_response == null) {
				m_response = new TimeStampResponse(m_responseContent);
			}

			return m_response;
		} catch (final TSPException exception) {
			throw new ClientException("Failed to read timestamp response from http response", exception);
		} catch (final IOException exception) {
			byte[] b = new byte[2];
			try {
				m_responseContent.reset();
				m_responseContent.read(b);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			throw new ClientException("Failed to read timestamp response from http response: " + new String(b),
					exception);
		}
	}

	public HttpTimestampClient unsafeSsl() {
		throw new UnsupportedOperationException("Not implemented");
	}

	public HttpTimestampClient x509Auth(final Certificate p_certificate) {
		throw new UnsupportedOperationException("Not implemented");
	}
}
