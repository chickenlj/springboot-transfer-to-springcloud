/*
 * Copyright 2002-2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.http.client;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import org.springframework.core.task.AsyncListenableTaskExecutor;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.cert.XdsSslStoreProvider;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

/**
 * {@link ClientHttpRequestFactory} implementation that uses standard JDK facilities.
 *
 * @author Arjen Poutsma
 * @author Juergen Hoeller
 * @since 3.0
 * @see java.net.HttpURLConnection
 * @see HttpComponentsClientHttpRequestFactory
 */
@SuppressWarnings("deprecation")
public class SimpleClientHttpRequestFactory implements ClientHttpRequestFactory, AsyncClientHttpRequestFactory {

	private static final int DEFAULT_CHUNK_SIZE = 4096;


	@Nullable
	private Proxy proxy;

	private boolean bufferRequestBody = true;

	private int chunkSize = DEFAULT_CHUNK_SIZE;

	private int connectTimeout = -1;

	private int readTimeout = -1;

	private boolean outputStreaming = true;

	@Nullable
	private AsyncListenableTaskExecutor taskExecutor;


	/**
	 * Set the {@link Proxy} to use for this request factory.
	 */
	public void setProxy(Proxy proxy) {
		this.proxy = proxy;
	}

	/**
	 * Indicate whether this request factory should buffer the
	 * {@linkplain ClientHttpRequest#getBody() request body} internally.
	 * <p>Default is {@code true}. When sending large amounts of data via POST or PUT,
	 * it is recommended to change this property to {@code false}, so as not to run
	 * out of memory. This will result in a {@link ClientHttpRequest} that either
	 * streams directly to the underlying {@link HttpURLConnection} (if the
	 * {@link org.springframework.http.HttpHeaders#getContentLength() Content-Length}
	 * is known in advance), or that will use "Chunked transfer encoding"
	 * (if the {@code Content-Length} is not known in advance).
	 * @see #setChunkSize(int)
	 * @see HttpURLConnection#setFixedLengthStreamingMode(int)
	 */
	public void setBufferRequestBody(boolean bufferRequestBody) {
		this.bufferRequestBody = bufferRequestBody;
	}

	/**
	 * Set the number of bytes to write in each chunk when not buffering request
	 * bodies locally.
	 * <p>Note that this parameter is only used when
	 * {@link #setBufferRequestBody(boolean) bufferRequestBody} is set to {@code false},
	 * and the {@link org.springframework.http.HttpHeaders#getContentLength() Content-Length}
	 * is not known in advance.
	 * @see #setBufferRequestBody(boolean)
	 */
	public void setChunkSize(int chunkSize) {
		this.chunkSize = chunkSize;
	}

	/**
	 * Set the underlying URLConnection's connect timeout (in milliseconds).
	 * A timeout value of 0 specifies an infinite timeout.
	 * <p>Default is the system's default timeout.
	 * @see URLConnection#setConnectTimeout(int)
	 */
	public void setConnectTimeout(int connectTimeout) {
		this.connectTimeout = connectTimeout;
	}

	/**
	 * Set the underlying URLConnection's read timeout (in milliseconds).
	 * A timeout value of 0 specifies an infinite timeout.
	 * <p>Default is the system's default timeout.
	 * @see URLConnection#setReadTimeout(int)
	 */
	public void setReadTimeout(int readTimeout) {
		this.readTimeout = readTimeout;
	}

	/**
	 * Set if the underlying URLConnection can be set to 'output streaming' mode.
	 * Default is {@code true}.
	 * <p>When output streaming is enabled, authentication and redirection cannot be handled automatically.
	 * If output streaming is disabled, the {@link HttpURLConnection#setFixedLengthStreamingMode} and
	 * {@link HttpURLConnection#setChunkedStreamingMode} methods of the underlying connection will never
	 * be called.
	 * @param outputStreaming if output streaming is enabled
	 */
	public void setOutputStreaming(boolean outputStreaming) {
		this.outputStreaming = outputStreaming;
	}

	/**
	 * Set the task executor for this request factory. Setting this property is required
	 * for {@linkplain #createAsyncRequest(URI, HttpMethod) creating asynchronous requests}.
	 * @param taskExecutor the task executor
	 */
	public void setTaskExecutor(AsyncListenableTaskExecutor taskExecutor) {
		this.taskExecutor = taskExecutor;
	}


	@Override
	public ClientHttpRequest createRequest(URI uri, HttpMethod httpMethod) throws IOException {
		HttpURLConnection connection = openConnection(uri.toURL(), this.proxy);
		prepareConnection(connection, httpMethod.name());

		if (this.bufferRequestBody) {
			return new SimpleBufferingClientHttpRequest(connection, this.outputStreaming);
		}
		else {
			return new SimpleStreamingClientHttpRequest(connection, this.chunkSize, this.outputStreaming);
		}
	}

	/**
	 * {@inheritDoc}
	 * <p>Setting the {@link #setTaskExecutor taskExecutor} property is required before calling this method.
	 */
	@Override
	public AsyncClientHttpRequest createAsyncRequest(URI uri, HttpMethod httpMethod) throws IOException {
		Assert.state(this.taskExecutor != null, "Asynchronous execution requires TaskExecutor to be set");

		HttpURLConnection connection = openConnection(uri.toURL(), this.proxy);
		prepareConnection(connection, httpMethod.name());

		if (this.bufferRequestBody) {
			return new SimpleBufferingAsyncClientHttpRequest(
					connection, this.outputStreaming, this.taskExecutor);
		}
		else {
			return new SimpleStreamingAsyncClientHttpRequest(
					connection, this.chunkSize, this.outputStreaming, this.taskExecutor);
		}
	}

	/**
	 * Opens and returns a connection to the given URL.
	 * <p>The default implementation uses the given {@linkplain #setProxy(java.net.Proxy) proxy} -
	 * if any - to open a connection.
	 * @param url the URL to open a connection to
	 * @param proxy the proxy to use, may be {@code null}
	 * @return the opened connection
	 * @throws IOException in case of I/O errors
	 */
	protected HttpURLConnection openConnection(URL url, @Nullable Proxy proxy) throws IOException {
//		url = tlsBefore(url);
		URLConnection urlConnection = (proxy != null ? url.openConnection(proxy) : url.openConnection());
		if (!(urlConnection instanceof HttpURLConnection)) {
			throw new IllegalStateException(
					"HttpURLConnection required for [" + url + "] but got: " + urlConnection);
		}
		tlsAfter(urlConnection);
		return (HttpURLConnection) urlConnection;
	}

	private URL tlsBefore(URL url) {
		try {
			if (!url.toURI().getPath().contains("https")) {
				return url;
			}

			URI uri = url.toURI();
			if ("http".equals(uri.getScheme())) {
				String uriSt = uri.toString();
				String uriStNew = uriSt.replaceFirst("http", "https");
				URI newUri = new URI(uriStNew);
				return newUri.toURL();
			}
			else {
				return url;
			}
		}
		catch (Exception e) {
			return url;
		}
	}

	private void tlsAfter(URLConnection connection) {

		if (connection instanceof HttpsURLConnection) {
			XdsSslStoreProvider xdsSslStoreProvider = new XdsSslStoreProvider();
			try {
				SSLContext sslContext = getSslContext(xdsSslStoreProvider);
				HttpsURLConnection httpsURLConnection = (HttpsURLConnection) connection;
				httpsURLConnection.setHostnameVerifier(new DefaultHostnameVerifier());
				httpsURLConnection.setSSLSocketFactory(sslContext.getSocketFactory());
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private static SSLContext getSslContext(XdsSslStoreProvider xdsSslStoreProvider) throws NoSuchAlgorithmException, KeyStoreException, UnrecoverableKeyException, KeyManagementException {
		KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
		keyManagerFactory.init(xdsSslStoreProvider.getClientKeyStore(), "".toCharArray());

		TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
		trustManagerFactory.init(xdsSslStoreProvider.getClientTrustStore());

		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(
				keyManagerFactory.getKeyManagers(),
				trustManagerFactory.getTrustManagers(),
				new SecureRandom()
		);
		return sslContext;
	}

	/**
	 * Template method for preparing the given {@link HttpURLConnection}.
	 * <p>The default implementation prepares the connection for input and output, and sets the HTTP method.
	 * @param connection the connection to prepare
	 * @param httpMethod the HTTP request method ({@code GET}, {@code POST}, etc.)
	 * @throws IOException in case of I/O errors
	 */
	protected void prepareConnection(HttpURLConnection connection, String httpMethod) throws IOException {
		if (this.connectTimeout >= 0) {
			connection.setConnectTimeout(this.connectTimeout);
		}
		if (this.readTimeout >= 0) {
			connection.setReadTimeout(this.readTimeout);
		}

		boolean mayWrite =
				("POST".equals(httpMethod) || "PUT".equals(httpMethod) ||
						"PATCH".equals(httpMethod) || "DELETE".equals(httpMethod));

		connection.setDoInput(true);
		connection.setInstanceFollowRedirects("GET".equals(httpMethod));
		connection.setDoOutput(mayWrite);
		connection.setRequestMethod(httpMethod);
	}

	private static class DefaultHostnameVerifier implements HostnameVerifier {
		private DefaultHostnameVerifier() {
		}

		public boolean verify(String hostname, SSLSession session) {
			return true;
		}
	}

}
