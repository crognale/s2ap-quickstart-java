package com.google.wallet.objects.webservice;

/**
 * Bean for Webservice API represents the message response from your server to
 * Google
 *
 * @author pying
 *
 */
public class WebserviceResponse {
  String message;
  String result;

  public WebserviceResponse() {
  }

  public WebserviceResponse(String message, String result) {
    setMessage(message);
    setResult(result);
  }

  public String getMessage() {
    return message;
  }

  public void setMessage(String message) {
    this.message = message;
  }

  public String getResult() {
    return result;
  }

  public void setResult(String result) {
    this.result = result;
  }
}
