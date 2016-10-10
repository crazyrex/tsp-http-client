package it.luigibifulco.crypto.tsa;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;

/**
 * 
 * @author Luigi Bifulco
 *
 */
public class TSAResponseViewer {

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

	public static void main(String[] args) throws IOException, TSPException {
		TSAResponseViewer viewer = new TSAResponseViewer("tsa-context/response_13401728521388604229.tsp");
		TimeStampResponse resp = viewer.loadResponseFromFile();
		viewer.traceInfo(resp);
	}
}
