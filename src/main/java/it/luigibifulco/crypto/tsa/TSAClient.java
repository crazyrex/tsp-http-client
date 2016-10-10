package it.luigibifulco.crypto.tsa;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpResponseException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;

import it.luigibifulco.crypto.tsa.rfc3161.DigestGenerator;
import it.luigibifulco.crypto.tsa.rfc3161.HttpTimestampClient;
import it.luigibifulco.crypto.tsa.rfc3161.NonceGenerator;
import it.luigibifulco.crypto.tsa.rfc3161.RequestGenerator;
import it.luigibifulco.crypto.tsa.rfc3161.config.Algorithm;
import it.luigibifulco.crypto.tsa.rfc3161.config.Configuration;
import it.luigibifulco.crypto.tsa.rfc3161.config.PkiStatus;
import it.luigibifulco.crypto.tsa.rfc3161.exceptions.Rfc3161Exception;

/**
 * 
 * @author Luigi Bifulco
 *
 */
public class TSAClient {

	private Configuration cfg;

	private File workDir;

	private DigestGenerator digestGenerator;

	private RequestGenerator requestGenerator;

	private HttpTimestampClient client;

	private TimeStampRequest timeStampRequest;

	public TSAClient() throws IOException {
		this.cfg = loadTsaProps();
	}

	protected Configuration loadTsaProps() throws IOException {
		Properties prop = new Properties();
		InputStream in = getClass().getResourceAsStream("tsp.properties");
		prop.load(in);
		Configuration cfg = new Configuration();
		cfg.setAlgorithm(
				Algorithm.valueOf(prop.getOrDefault("tsp.digestAlgorithm", Algorithm.SHA256.name()).toString()));
		cfg.setCertReq(Boolean.valueOf(prop.getOrDefault("tsp.requestCert", true).toString()));
		cfg.setGenNonce(true);
		cfg.setData(prop.getProperty("tsp.dataPath"));
		cfg.setUrl(prop.getProperty("tsp.url"));
		cfg.setUser(prop.getProperty("tsp.username"));
		cfg.setPassword(prop.getProperty("tsp.password"));
		workDir = new File(prop.getProperty("tsp.workdir"));
		if (!workDir.exists()) {
			workDir.mkdirs();
		}
		return cfg;

	}

	protected void initDigest() {
		digestGenerator = new DigestGenerator(cfg.getData(), cfg.getAlgorithm());
		digestGenerator.initDigest().initFile().generateDigest();
		digestGenerator.storeDigest(workDir.getAbsolutePath() + "/digest." + cfg.getAlgorithm().name());
	}

	protected void initRequestGenerator() {
		requestGenerator = new RequestGenerator(cfg.getAlgorithm(), digestGenerator.digest())
				.certReq(cfg.isCertReq());
		requestGenerator.nonce(NonceGenerator.generateNonce());
	}

	protected void doRequest() throws HttpResponseException {
		timeStampRequest = requestGenerator.request();
		requestGenerator.storeRequest(workDir.getAbsolutePath() + "/request_" + timeStampRequest.getNonce() + ".tsp");
		client = new HttpTimestampClient(cfg.getUrl(), cfg.getUser(), cfg.getPassword(),
				timeStampRequest);
		client.initClient().execute();
		if (client.httpStatus() != HttpStatus.SC_OK) {
			throw new HttpResponseException(client.httpStatus(), "Http response not ok: " + client.httpStatus());
		}
	}

	protected void doResponse() {
		TimeStampResponse timestampResponse = client.timestampResponse();
		if (!PkiStatus.isGranted(timestampResponse.getStatus())) {
			System.out.println(String.format("RFC3161 token not granted with status: %s - %s",
					PkiStatus.forStatus(timestampResponse.getStatus()), timestampResponse.getStatusString()));
		}
		final File responseFile = new File(
				workDir.getAbsolutePath() + "/response_" + timeStampRequest.getNonce() + ".tsp");
		try {
			final OutputStream output = new FileOutputStream(responseFile);
			IOUtils.write(timestampResponse.getEncoded(), output);
			output.close();
		} catch (final IOException exception) {
			throw new Rfc3161Exception(exception.getMessage(), exception);
		}
	}

	public void queryTimestamp() throws HttpResponseException {
		initDigest();
		initRequestGenerator();
		doRequest();
		doResponse();
	}

	public static void main(String[] args) throws IOException {
		TSAClient client = new TSAClient();
		client.queryTimestamp();
	}
}
