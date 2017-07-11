package it.luigibifulco.crypto.tsa;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;
import org.bouncycastle.tsp.cms.CMSTimeStampedData;
import org.bouncycastle.tsp.cms.CMSTimeStampedDataGenerator;
import org.bouncycastle.tsp.cms.ImprintDigestInvalidException;
import org.bouncycastle.util.encoders.Hex;


/**
 * 
 * @author Luigi Bifulco
 *
 */
public class TSAResponseViewer {
	
	private static SimpleDateFormat dateFormatGmt = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss zzz");

	static {
		dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
	}

	private File responseFile;

	public TSAResponseViewer(String path) {
		responseFile = new File(path);

	}

	public TimeStampResponse loadResponseFromFile() throws IOException, TSPException {
		byte[] content = FileUtils.readFileToByteArray(responseFile);
		TimeStampResponse response = new TimeStampResponse(content);
		return response;
	}

	public void traceInfo(TimeStampResponse response) {
		System.out.println("Time info: " + response.getTimeStampToken().getTimeStampInfo().getGenTime());
		System.out.println("Nonce: " + response.getTimeStampToken().getTimeStampInfo().getNonce());
		System.out.println("Algorithm info: "
				+ response.getTimeStampToken().getTimeStampInfo().getHashAlgorithm().getAlgorithm().getId());

	}

	public static void main(String[] args) throws IOException, TSPException, OperatorCreationException, CMSException, ImprintDigestInvalidException {
		TSAResponseViewer viewer = new TSAResponseViewer("target/response_8548437722049662778.tsp");
		File data = new File("./tsa-context/test.txt");
		FileInputStream dataStream = new FileInputStream(data);
		TimeStampResponse resp = viewer.loadResponseFromFile();
		viewer.traceInfo(resp);
		resp.getTimeStampToken();
		
		validateDigestValue(resp.getTimeStampToken(), dataStream);
		TimeStampTokenInfo theSignedPayload = resp.getTimeStampToken().getTimeStampInfo();
		String HashAlgorithm = theSignedPayload.getHashAlgorithm().getAlgorithm().toString();
		String HashValue = new String(Hex.encode(theSignedPayload.getMessageImprintDigest()));
		String protectionTime = theSignedPayload.getGenTime().toString();
		System.out.println(protectionTime);
		System.out.print(dateFormatGmt.format(theSignedPayload.getGenTime()));
		System.out.println(" Protected hash (" + HashAlgorithm + "): " + HashValue);
		System.exit(0);
	}
	
	public static void validateDigestValue(TimeStampToken aTimestamp, FileInputStream theProtectedData)
			throws CMSException, OperatorCreationException, IOException, ImprintDigestInvalidException {
		CMSTimeStampedDataGenerator aUtility = new CMSTimeStampedDataGenerator();
		CMSTimeStampedData aCMSTimeStampedData = null;
		if (theProtectedData != null) {
			aCMSTimeStampedData = aUtility.generate(aTimestamp, theProtectedData);
			testValidateAllTokens(aCMSTimeStampedData);
		}
	}
	
	public static void testValidateAllTokens(CMSTimeStampedData cmsTimeStampedData)
			throws OperatorCreationException, IOException, CMSException, ImprintDigestInvalidException {
		DigestCalculatorProvider digestCalculatorProvider = new BcDigestCalculatorProvider();

		DigestCalculator imprintCalculator = cmsTimeStampedData
				.getMessageImprintDigestCalculator(digestCalculatorProvider);

		imprintCalculator.getOutputStream().write(cmsTimeStampedData.getContent());

		byte[] digest = imprintCalculator.getDigest();

		TimeStampToken[] tokens = cmsTimeStampedData.getTimeStampTokens();
		for (int i = 0; i < tokens.length; i++) {
			cmsTimeStampedData.validate(digestCalculatorProvider, digest, tokens[i]);
		}
	}
}
