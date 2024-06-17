/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.http.client.cert;

import java.security.KeyStore;

import org.springframework.boot.web.server.SslStoreProvider;

public class XdsSslStoreProvider implements SslStoreProvider {

	public KeyStore getKeyStore(CertPair certPair) {
		try {
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null, null);
			keyStore.setKeyEntry("mtls_default_key_store_alias",
					certPair.getPrivateKey(), "".toCharArray(),
					certPair.getCertificateChain());
			return keyStore;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public KeyStore getKeyStore() {
		CertPair certPair = TlsCenterTest.getCertPair();
		return getKeyStore(certPair);
	}

	public KeyStore getClientKeyStore() {
		CertPair certPair = TlsCenterTest.getClientCertPair();
		return getKeyStore(certPair);
	}

	public KeyStore getTrustStore(CertPair certPair) {
		try {
			KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			keyStore.load(null, null);
			keyStore.setCertificateEntry("mtls_default_trust_store_alias",
					certPair.getRootCA());
			return keyStore;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public KeyStore getTrustStore() {
		CertPair certPair = TlsCenterTest.getCertPair();
		return getTrustStore(certPair);
	}

	public KeyStore getClientTrustStore() {
		CertPair certPair = TlsCenterTest.getClientCertPair();
		return getTrustStore(certPair);
	}

}
