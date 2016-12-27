using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using SAMLIdentityProvider.Library.Schema;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using System.Web.Routing;
using System.Xml.Serialization;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Security.Cryptography.X509Certificates;

namespace AuthorisationServer.Controllers
{
    public class OAuthController : Controller
    {
        //Trusted sources of request and redirect urls
        private List<string> trustedSAMLIdProviders;

        //List of federated user names
        private List<string> federatedUsers;

        public OAuthController()
        {
            //Initialize fields
            trustedSAMLIdProviders = new List<string>()
            {
                "SAMLIdentityProvider"
            };
            federatedUsers = new List<string>()
            {
                "federatedusername"
            };
        }

        public ActionResult Authorize()
        {
            if (Response.StatusCode != 200)
            {
                return View("AuthorizeError");
            }

            var authentication = HttpContext.GetOwinContext().Authentication;

            //If the saml response was successfully parsed the identity should be set
            var ticket = authentication.AuthenticateAsync("Application").Result;
            var identity = ticket != null ? ticket.Identity : null;
            if (identity == null)
            {
                return View("Error");
            }

            if (Request.HttpMethod == "POST")
            {
                if (!string.IsNullOrEmpty(Request.Form.Get("submit.Grant")))
                {
                    //User clicked grant - add the scope claims
                    identity = new ClaimsIdentity(
                        identity.Claims, 
                        OAuthDefaults.AuthenticationType, 
                        identity.NameClaimType, 
                        identity.RoleClaimType
                        );
                    var scopes = (Request.QueryString.Get("scope") ?? "").Split(' ');

                    foreach (var scope in scopes)
                    {
                        identity.AddClaim(new Claim("urn:oauth:scope", scope));
                    }

                    authentication.SignIn(identity);
                }
                if (!string.IsNullOrEmpty(Request.Form.Get("submit.Decline")))
                {
                    authentication.SignOut("Application");

                    return Redirect("http://localhost:33222");
                }
            }

            return View();
        }
        
        [HttpPost]
        public ActionResult SAMLAuthorize(string samlToken)
        {
            var authentication = HttpContext.GetOwinContext().Authentication;

            //Extract SAMLResponse and verify signature
            string samlResponseXML = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(samlToken));
            string username;

            //Check the signature
            if (TokenValid(samlResponseXML, out username) && SignatureValid(samlResponseXML))
            {
                //Create claims identity with the user login from the SAML response
                ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[] {
                    new Claim(ClaimsIdentity.DefaultNameClaimType, username)
                }, "Application");

                //Store hash of the SAML response to be checked against
                //when receiving the oauth code
                HttpRuntime.Cache[username] = samlToken.GetHashCode();

                //Sign in - this creates the cookie with the identity
                authentication.SignIn(
                    new AuthenticationProperties
                    {
                        IsPersistent = false,
                        RedirectUri = Request.Params["redirect_uri"]
                    },
                    claimsIdentity
                    );

                return RedirectToAction("Authorize", 
                    new RouteValueDictionary(new Dictionary<string, object>()
                            {
                                { "client_id", username },
                                { "redirect_uri", Request.Params["redirect_uri"] },
                                { "state", Request.Params["state"] },
                                { "scope", Request.Params["scope"] },
                                { "response_type", Request.Params["response_type"] }
                            }));
            }            

            return View("Error");
        }

        /// <summary>
        /// Checks whether the issuer of the SAML is trusted and whether the user is known and authenticated successfully.
        /// </summary>
        private bool TokenValid(string samlXML, out string username)
        {
            XmlSerializer serializer = new XmlSerializer(typeof(ResponseType));
            ResponseType response = (ResponseType)serializer.Deserialize(new StringReader(samlXML));

            bool issuerTrusted = trustedSAMLIdProviders.Contains(response.Issuer.Value);
            bool statusSuccess = response.Status.StatusCode.Value.Equals("urn:oasis:names:tc:SAML:2.0:status:Success");
            bool userIsKnown = false;
            username = null;

            //Find assertion
            AssertionType assertion = null;
            foreach (var item in response.Items)
            {
                if (item is AssertionType)
                {
                    assertion = item as AssertionType;
                }
            }

            //Find the username
            if (assertion != null)
            {
                foreach (var item in assertion.Subject.Items)
                {
                    if (item is NameIDType)
                    {

                        if (!string.IsNullOrEmpty(((NameIDType)item).Value))
                        {
                            userIsKnown = federatedUsers.Contains(((NameIDType)item).Value);
                            username = ((NameIDType)item).Value;

                        }
                    }
                }
            }

            if (issuerTrusted && statusSuccess && userIsKnown)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Checks whether the SAML signature is valid
        /// </summary>
        private bool SignatureValid(string samlXML)
        {
            XmlDocument xmlDoc = new XmlDocument() { PreserveWhitespace = true };
            xmlDoc.LoadXml(samlXML);
            SignedXml signedXML = new SignedXml(xmlDoc);

            string certPath = System.Web.Hosting.HostingEnvironment.MapPath(@"~/App_Data/TestCert.cer");
            X509Certificate2 signingCertificate = new X509Certificate2(certPath);

            XmlNodeList signatureElement = xmlDoc.GetElementsByTagName("Signature");
            signedXML.LoadXml((XmlElement)signatureElement[0]);

            return signedXML.CheckSignature(signingCertificate, true);
        }
    }
}