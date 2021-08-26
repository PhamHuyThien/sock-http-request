
package com.thiendz.lib.request;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.security.Permission;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SockHttpRequest {

	private static final String NEWLINE_STR = "\r\n";
	//
	private Socket socket;
	private URL url;
	//
	private String proxyHost;
	private int proxyPort;
	private String proxyUsername;
	private String proxyPassword;
	//
	private final Map<String, List<String>> mProperties;
	private final Map<String, List<String>> mHeaders;
	//
	private String requestMethod;
	private int connectTimeout;
	//
	private int responseCode;
	private String responseMessage;
	private String responseBody;
	//
	private InputStream inputStream;
	//
	private boolean connected;
	private boolean close;

	//
	public SockHttpRequest(String url) throws MalformedURLException {
		this(new URL(url));
	}

	public SockHttpRequest(URL url) {
		this.url = url;
		socket = new Socket();
		mProperties = new HashMap<>();
		mHeaders = new HashMap<>();
		requestMethod = GET;
	}

	public void setRequestMethod(String method) {
		this.requestMethod = method;
	}

	public String getRequestMethod() {
		return requestMethod;
	}

	public void setRequestProperty(String key, String value) {
		ArrayList<String> al = new ArrayList<>();
		al.add(value);
		mProperties.put(key.toLowerCase(), al);
	}

	public void addRequestProperty(String key, String value) {
		mProperties.computeIfAbsent(key, l -> new ArrayList<>()).add(value);
	}

	public Map<String, List<String>> getRequestProperties() {
		return mProperties;
	}

	public void setProxy(String proxyHost, int proxyPort) {
		this.proxyHost = proxyHost;
		this.proxyPort = proxyPort;
	}

	public boolean usingProxy() {
		return proxyHost != null && proxyPort != 0;
	}

	public void setProxyAuth(String proxyUsername, String proxyPassword) {
		this.proxyUsername = proxyUsername;
		this.proxyPassword = proxyPassword;
	}

	public boolean usingProxyAuth() {
		return proxyUsername != null && proxyPassword != null;
	}

	public int getConnectTimeout() {
		return connectTimeout;
	}

	public void setConnectTimeout(int connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	private void setConnected(boolean connected) {
		this.connected = connected;
	}

	public boolean isConnected() {
		return connected;
	}

	private void setClose(boolean close) {
		this.close = close;
	}

	public boolean isClose() {
		return close;
	}

	public OutputStream getOutputStream() throws IOException {
		connect();
		return socket.getOutputStream();
	}

	public void connect() throws IOException {
		if (isConnected()) {
			return;
		}
		setConnected(true);
		//
		String host = url.getHost();
		int port = url.getPort() == -1 ? 443 : url.getPort();
		//
		StringBuilder sbRequest = new StringBuilder();
		//
		ArrayList<String> al = new ArrayList<>();
		final String HEADER_KEY_ACCEPT = "accept";
		final String HEADER_KEY_CONNECTION = "connection";
		if (!mProperties.containsKey(HEADER_KEY_ACCEPT)) {
			al.add("*/*");
			mProperties.put(HEADER_KEY_ACCEPT, al);
		}
		if (!mProperties.containsKey(HEADER_KEY_CONNECTION)) {
			al.clear();
			al.add("close");
			mProperties.put(HEADER_KEY_CONNECTION, al);
		}
		//
		socket.setSoTimeout(getConnectTimeout());
		//
		// ================================ CONNECT USING PROXY
		// ================================//
		if (this.usingProxy()) {
			socket.connect(new InetSocketAddress(proxyHost, proxyPort), getConnectTimeout());
			// CONNECT {HOST}:{PORT} HTTP/1.1
			sbRequest.append(CONNECT).append(" ").append(host).append(":").append(port).append(" HTTP/1.1")
					.append(NEWLINE_STR);
			if (usingProxyAuth()) {
				// proxy-authorization: Basic XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
				byte[] byteAuth = (proxyUsername + ":" + proxyPassword).getBytes();
				String proxyAuthEncode = "Basic " + Base64.getEncoder().encodeToString(byteAuth);
				sbRequest.append("proxy-authorization").append(": ").append(proxyAuthEncode).append(NEWLINE_STR);
			}
			sbRequest.append("connection: close").append(NEWLINE_STR).append(NEWLINE_STR);
			//
			socket.getOutputStream().write(sbRequest.toString().getBytes());
			socket.getOutputStream().flush();
			//
			String replyStatus = toBufferedReader(socket.getInputStream()).readLine();
			if (!replyStatus.startsWith("HTTP/1.1 200") && !replyStatus.startsWith("HTTP/1.0 200")) {
				responseCode = parseResponseCode(replyStatus);
				responseMessage = parseResponseMessage(replyStatus);
				return;
			}
		}
		// ================================ REQUEST ================================//
		sbRequest.setLength(0);
		SSLSocketFactory sslsf = (SSLSocketFactory) SSLSocketFactory.getDefault();
		SSLSocket sslSocket;
		if (socket.isConnected()) {
			sslSocket = (SSLSocket) sslsf.createSocket(socket, host, port, true);
		} else {
			sslSocket = (SSLSocket) sslsf.createSocket(host, port);
		}
		sslSocket.startHandshake();
		socket = sslSocket;
		// {METHOD} {FILEPATH} HTTP/1.1\r\n
		String filePath = url.getFile();
		filePath = filePath.equals("") ? "/" : filePath;
		sbRequest.append(getRequestMethod()).append(" ").append(filePath).append(" HTTP/1.1").append(NEWLINE_STR);
		// Host: {HOST}\r\n
		sbRequest.append("host: ").append(host).append(NEWLINE_STR);
		// {KEY}: {VALUE}\r\n
		mProperties.entrySet().forEach(mProperty -> {
			sbRequest.append(mProperty.getKey()).append(": ").append(String.join("; ", mProperty.getValue()))
					.append(NEWLINE_STR);
		});
		sbRequest.append(NEWLINE_STR);
		socket.getOutputStream().write(sbRequest.toString().getBytes());
		socket.getOutputStream().flush();
	}

	public InputStream getInputStream() throws IOException {
		connect();
		if (isClose()) {
			return inputStream;
		}
		setClose(true);
        BufferedReader br = toBufferedReader(socket.getInputStream());
		StringBuilder strResponseBody = new StringBuilder();
        String strLine;
        int intLine = 0;
        while ((strLine = br.readLine()) != null) {
            if (intLine == 0) {
                responseCode = parseResponseCode(strLine);
                responseMessage = parseResponseMessage(strLine);
                intLine++;
            } else if (intLine > 0) {
                if (strLine.trim().equals("")) {
                    intLine = -1;
                    continue;
                }
                int indexPair = strLine.indexOf(":");
                String headerKey = strLine.substring(0, indexPair);
                String headerValue = strLine.substring(indexPair+1);
                addHeaderField(headerKey.trim(), headerValue.trim());
                intLine++;
            } else {
                strResponseBody.append(strLine).append("\n");
            }
        }
//		InputStream is = socket.getInputStream();
//		int k;
//		while ((k = is.read()) != -1) {
//			strResponseBody.append((char) k);
//		}
		responseBody = strResponseBody.toString();
        inputStream = new ByteArrayInputStream(responseBody.getBytes());
//		inputStream = is;
		return inputStream;
	}

	private void addHeaderField(String key, String value) {
		mHeaders.computeIfAbsent(key, l -> new ArrayList<>()).add(value);
	}

	public List<String> getHeaderField(String key) throws IOException {
		connect();
		getInputStream();
		return mHeaders.get(key);
	}

	public Map<String, List<String>> getHeaderFields() throws IOException {
		connect();
		getInputStream();
		return mHeaders;
	}

	public int getResponseCode() throws IOException {
		connect();
		getInputStream();
		return responseCode;
	}

	public String getResponseMessage() throws IOException {
		connect();
		getInputStream();
		return responseMessage;
	}

	public String getResponseBody() throws IOException {
		connect();
		getInputStream();
		return responseBody;
	}

	public void disconnect() throws IOException {
		if (isConnected()) {
			socket.close();
		}
	}

	@Deprecated
	public boolean getAllowUserInteraction() {
		return false;
	}

	@Deprecated
	public Object getContent() {
		return null;
	}

	@Deprecated
	public String getContentEncoding() {
		return null;
	}

	@Deprecated
	public int getContentLength() {
		return -1;
	}

	@Deprecated
	public long getContentLengthLong() {
		return -1;
	}

	@Deprecated
	public String getContentType() {
		return null;
	}

	@Deprecated
	public long getDate() {
		return -1;
	}

	@Deprecated
	public boolean getDefaultUseCaches() {
		return false;
	}

	@Deprecated
	public boolean getDoInput() {
		return false;
	}

	@Deprecated
	public boolean getDoOutput() {
		return false;
	}

	@Deprecated
	public InputStream getErrorStream() {
		return null;
	}

	@Deprecated
	public long getExpiration() {
		return -1;
	}

	@Deprecated
	public long getHeaderFieldDate(String name, long Default) {
		return -1;
	}

	@Deprecated
	public int getHeaderFieldInt(String name, int Default) {
		return -1;
	}

	@Deprecated
	public String getHeaderFieldKey(int n) {
		return null;
	}

	@Deprecated
	public long getHeaderFieldLong(String name, long Default) {
		return -1;
	}

	@Deprecated
	public long getIfModifiedSince() {
		return -1;
	}

	@Deprecated
	public boolean getInstanceFollowRedirects() {
		return false;
	}

	@Deprecated
	public long getLastModified() {
		return -1;
	}

	@Deprecated
	public Permission getPermission() {
		return null;
	}

	@Deprecated
	public void setAllowUserInteraction(boolean allowuserinteraction) {
	}

	@Deprecated
	public void setChunkedStreamingMode(int chunked) {
	}

	@Deprecated
	public void setDefaultUseCaches(boolean defaultUseCaches) {
	}

	@Deprecated
	public void setDoInput(boolean doInput) {
	}

	@Deprecated
	public void setDoOutput(boolean doOuput) {
	}

	@Deprecated
	public void setFixedLengthStreamingMode(int contentLength) {
	}

	@Deprecated
	public void setFixedLengthStreamingMode(long contentLength) {
	}

	@Deprecated
	public void setIfModifiedSince(long ifModifiedSince) {
	}

	@Deprecated
	public void setInstanceFollowRedirects(boolean followRedirects) {
	}

	@Deprecated
	public void setUseCaches(boolean useCaches) {
	}

	private static BufferedReader toBufferedReader(InputStream inputStream) {
		try {
			return new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));
		} catch (UnsupportedEncodingException ex) {
			return null;
		}
	}

	private static int parseResponseCode(String response) {
		int index = response.indexOf(" ") + 1;
		return Integer.parseInt(response.substring(index, index + 3));
	}

	private static String parseResponseMessage(String response) {
		int index = response.indexOf(" ") + 4;
		return response.substring(index + 1);
	}

	// METHOD
	public static final String POST = "POST";
	public static final String PUT = "PUT";
	public static final String GET = "GET";
	public static final String DELETE = "DELETE";
	public static final String TRADE = "TRADE";
	public static final String CONNECT = "CONNECT";
	public static final String OPTIONS = "OPTIONS";
	public static final String PATCH = "PATCH";
	public static final String HEAD = "HEAD";
}