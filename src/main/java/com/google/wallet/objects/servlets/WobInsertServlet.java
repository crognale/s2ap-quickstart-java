package com.google.wallet.objects.servlets;

import com.google.api.client.json.GenericJson;
import com.google.api.services.walletobjects.Walletobjects;
import com.google.api.services.walletobjects.model.GiftCardClass;
import com.google.api.services.walletobjects.model.LoyaltyClass;
import com.google.api.services.walletobjects.model.OfferClass;
import com.google.wallet.objects.utils.Config;
import com.google.wallet.objects.utils.WobClientFactory;
import com.google.wallet.objects.utils.WobCredentials;
import com.google.wallet.objects.verticals.GiftCard;
import com.google.wallet.objects.verticals.Loyalty;
import com.google.wallet.objects.verticals.Offer;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.GeneralSecurityException;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This servlet handles requests to insert new Wallet Classes. It parses the
 * type URL parameter to determine the type and generates the respective Class to
 * insert. The valid types are: loyalty, offers, or giftcard.
 *
 * @author pying
 */
@SuppressWarnings("serial")
public class WobInsertServlet extends HttpServlet {

  public void doGet(HttpServletRequest req, HttpServletResponse resp) {

    // Access credentials from web.xml
    ServletContext context = getServletContext();

    Config config = Config.getInstance();

    // Create a credentials object
    WobCredentials credentials = null;
    Walletobjects client = null;

    try {
      credentials = config.getCredentials(context);
      client = WobClientFactory.getWalletObjectsClient(credentials);
    } catch (IOException e) {
      e.printStackTrace();
      return;
    } catch (GeneralSecurityException e) {
      e.printStackTrace();
      return;
    }

    // Get request typehich
    String type = req.getParameter("type");

    GenericJson response = null;

    // Create and insert type
    try {
        if (type.equals("loyalty")) {
            LoyaltyClass loyaltyClass = Loyalty.generateLoyaltyClass(
                    credentials.getIssuerId(), context.getInitParameter("LoyaltyClassId"));
            response = client.loyaltyclass().insert(loyaltyClass).execute();
        } else if (type.equals("offer")) {
            OfferClass offerClass = Offer.generateOfferClass(credentials.getIssuerId(),
                    context.getInitParameter("OfferClassId"));
            response = client.offerclass().insert(offerClass).set("strict", "true").execute();
        } else if (type.equals("giftcard")) {
            GiftCardClass giftCardClass = GiftCard.generateGiftCardClass(credentials.getIssuerId(),
                    context.getInitParameter("GiftCardClassId"));
            response = client.giftcardclass().insert(giftCardClass).execute();
        }
    } catch (IOException e) {
        e.printStackTrace();
        return;
    }

    // Respond to request with class json
    PrintWriter out = null;
    try {
      out = resp.getWriter();
    } catch (IOException e) {
      e.printStackTrace();
      return;
    }

    out.write(response.toString());
  }
}
