package com.google.wallet.objects.utils;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.SecurityUtils;
import com.google.common.io.ByteStreams;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Class to define Wallet Object related credentials. These credentials are used
 * with WobUtils to simplify the OAuth token generation and JWT signing.
 * <p/>
 * If you're using a key file, specify the jsonKeyPath using the first
 * constructor. 
 *
 * @author pying, crognale
 */
public class WobCredentials {
  String serviceAccountId;
  String serviceAccountJsonKeyPath;
  String applicationName;
  String issuerId;
  public static final HttpTransport httpTransport = new NetHttpTransport();
  public static final JsonFactory jsonFactory = new GsonFactory();

  public static final List<String> scopes = Collections.unmodifiableList(Arrays.asList(
      "https://www.googleapis.com/auth/wallet_object.issuer",
      "https://www.googleapis.com/auth/wallet_object_sandbox.issuer"));

  private GoogleCredential gCredential;


  /**
   * Constructor for defining a path to your key.json file.
   *
   * @param serviceAccountId
   * @param jsonKeyPath
   * @param applicationName
   * @param issuerId
   */
  public WobCredentials(String serviceAccountId, String jsonKeyPath,
      String applicationName, String issuerId) throws IOException, GeneralSecurityException {
    setServiceAccountId(serviceAccountId);
		setServiceAccountJsonKeyPath(jsonKeyPath);
    setApplicationName(applicationName);
    setIssuerId(issuerId);
    generateGoogleCredential();
  }


  /**
   * Helper function to generate the Google Credential
   *
   * @return
   * @throws GeneralSecurityException
   * @throws IOException
	 * @throws FileNotFoundException
   */
  private void generateGoogleCredential() throws IOException, FileNotFoundException {
		InputStream keyAsStream = new FileInputStream(serviceAccountJsonKeyPath);
		gCredential = GoogleCredential.fromStream(keyAsStream).createScoped(scopes);
  }

  /**
   * @return the serviceAccountId
   */
  public String getServiceAccountId() {
    return serviceAccountId;
  }

	/**
	 * @return the private key needed to sign JWTs
	 */
	public RSAPrivateKey getRsaPrivateKey() {
		return (RSAPrivateKey) gCredential.getServiceAccountPrivateKey();
	}

  /**
   * @param serviceAccountId the serviceAccountId to set
   */
  public void setServiceAccountId(String serviceAccountId) {
    this.serviceAccountId = serviceAccountId;
  }

  /**
   * @return the serviceAccountJsonKeyPath
   */
  public String getServiceAccountJsonKeyPath() {
    return serviceAccountJsonKeyPath;
  }

  /**
   * @param serviceAccountJsonKeyPath the serviceAccountJsonKey to set
   */
  public void setServiceAccountJsonKeyPath(String serviceAccountJsonKey) {
    this.serviceAccountJsonKeyPath = serviceAccountJsonKey;
  }

  /**
   * @return the applicationName
   */
  public String getApplicationName() {
    return applicationName;
  }

  /**
   * @param applicationName the applicationName to set
   */
  public void setApplicationName(String applicationName) {
    this.applicationName = applicationName;
  }

  /**
   * @return the issuerId
   */
  public String getIssuerId() {
    return issuerId;
  }

  /**
   * @param issuerId the issuerId to set
   */
  public void setIssuerId(String issuerId) {
    this.issuerId = issuerId;
  }

  public String toString() {
    StringBuilder sb =
        new StringBuilder().append(serviceAccountId).append(serviceAccountJsonKeyPath).append(applicationName)
            .append(issuerId);
    return sb.toString();
  }

  public GoogleCredential getGoogleCredential() {
    return gCredential;
  }

  /**
   * Refreshes the access token and returns it.  You do not need to explicitly call this function.
   * You should only call it for one offs, like a script to request access tokens.
   *
   * @return OAuth access token
   * @throws GeneralSecurityException
   * @throws IOException
   */
  public String accessToken() throws GeneralSecurityException, IOException {
    gCredential.refreshToken();
    return gCredential.getAccessToken();
  }

}
