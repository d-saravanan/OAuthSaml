using SAMLIdentityProvider.Library;
using SAMLIdentityProvider.Library.Schema;
using SAMLIdentityProvider.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Web.Mvc;
using System.Xml.Serialization;

namespace SAMLIdentityProvider.Controllers
{
    public class SAMLController : Controller
    {
        private const string client = "http://localhost:33222";
        private const string clientReturnURL = client + "/Client/AuthnResponse";

        //Trusted sources of request and return urls
        private Dictionary<string, string> trusted = new Dictionary<string,string>()
        {
            { client, clientReturnURL }
        };

        //Mapping from local username to federated username agreed between the SAML authentication and OAuth authorisation servers
        private Dictionary<string, string> userMappings = new Dictionary<string, string>()
        {
            { "user", "federatedusername" }
        };

        /// <summary>
        /// Checks if the client request is valid and shows the login form
        /// </summary>
        /// <param name="samlRequest">SAML request by the client</param>
        //GET /SAML/AuthnRequest?SAMLRequest=base64encodedSAMLAuthnRequest
        public ActionResult AuthnRequest(string samlRequest)
        {
            if(samlRequest != null)
            {
                //Extract SAMLRequest
                XmlSerializer serializer = new XmlSerializer(typeof(AuthnRequestType));

                string samlRequestXML = 
                    System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(samlRequest));

                AuthnRequestType authnRequest = 
                    (AuthnRequestType)serializer.Deserialize(new StringReader(samlRequestXML));

                if(trusted.ContainsKey(authnRequest.Issuer.Value))
                {
                    ViewBag.requester = authnRequest.Issuer.Value;

                    //user enters credentials
                    return View("Login");
                }
                else
                {
                    //Source of request not trusted
                    return View("NotTrusted");
                }              
            }            

            return View();
        }  

        /// <summary>
        /// Authenticates the user and sends back the SAML Response
        /// </summary>
        /// <param name="user">User credentials</param>
        /// <param name="requester">Client requesting the login</param>
        //POST /SAML/AuthenticateUser
        [HttpPost]
        public ActionResult AuthenticateUser(User user, string requester)
        {
            ViewBag.ErrorMsg = null;

            if (user.Username == "user" && user.Password == "password")
            {
                string subject;
                userMappings.TryGetValue(user.Username, out subject);

                //Build SAMLResponse
                string certPath = 
                    System.Web.Hosting.HostingEnvironment.MapPath(@"~/App_Data/TestCert.pfx");

                X509Certificate2 signingCertificate = new X509Certificate2(certPath);
                ViewBag.SAMLResponse = SAML20Assertion.CreateSAML20Response(
                    "SAMLIdentityProvider", 60, "Audience", subject , 
                    requester, new Dictionary<string, string>(), signingCertificate
                    );
                ViewBag.ResponseURL = trusted[requester] + "?username=" + subject;

                //form to post the SAMLResponse
                return View("ClientRedirect");
            }
            else
            {
                ViewBag.ErrorMsg = "Invalid credentials";

                return View("AuthnRequest");
            }
        }    
    }
}
