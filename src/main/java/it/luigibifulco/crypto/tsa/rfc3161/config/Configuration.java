package it.luigibifulco.crypto.tsa.rfc3161.config;

/**
 * 
 * @author Luigi Bifulco
 *
 */
public class Configuration {

	private String m_data;

	private String m_digestFile;

	private String m_queryFile;

	private String m_responseFile;

	private boolean m_certReq;

	private String m_url;

	private Verbosity m_verbosity;

	private Algorithm m_algorithm = Algorithm.SHA1;

	private boolean m_genNonce = false;

	private String m_nonce;

	private String m_policyId;

	private boolean m_helpAsked;

	private String user;

	private String password;

	public Algorithm getAlgorithm() {
		return m_algorithm;
	}

	public String getData() {
		return m_data;
	}

	public String getDigestFile() {
		return m_digestFile;
	}

	public String getNonce() {
		return m_nonce;
	}

	public String getPolicyId() {
		return m_policyId;
	}

	public String getQueryFile() {
		return m_queryFile;
	}

	public String getResponseFile() {
		return m_responseFile;
	}

	public String getUrl() {
		return m_url;
	}

	public Verbosity getVerbosity() {
		return m_verbosity;
	}

	public boolean isCertReq() {
		return m_certReq;
	}

	public boolean isGenNonce() {
		return m_genNonce;
	}

	public boolean isHelpAsked() {
		return m_helpAsked;
	}

	public boolean isVerbose() {
		return m_verbosity != null;
	}

	public void setAlgorithm(final Algorithm p_algorithm) {
		m_algorithm = p_algorithm;
	}

	public void setCertReq(final boolean p_certReq) {
		m_certReq = p_certReq;
	}

	public void setData(final String p_data) {
		m_data = p_data;
	}

	public void setDigestFile(final String p_digestFile) {
		m_digestFile = p_digestFile;
	}

	public void setGenNonce(final boolean p_genNonce) {
		m_genNonce = p_genNonce;
	}

	public void setHelpAsked(final boolean p_helpAsked) {
		m_helpAsked = p_helpAsked;
	}

	public void setNonce(final String p_nonce) {
		m_nonce = p_nonce;
	}

	public void setPolicyId(final String p_policyId) {
		m_policyId = p_policyId;
	}

	public void setQueryFile(final String p_queryFile) {
		m_queryFile = p_queryFile;
	}

	public void setResponseFile(final String p_responseFile) {
		m_responseFile = p_responseFile;
	}

	public void setUrl(final String p_url) {
		m_url = p_url;
	}

	public void setVerbosity(final Verbosity p_verbosity) {
		m_verbosity = p_verbosity;
	}

	public String getUser() {
		return user;
	}

	public void setUser(String user) {
		this.user = user;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

}
