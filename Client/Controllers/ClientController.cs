using Client.Utils;
using Newtonsoft.Json.Linq;
using SAMLIdentityProvider.Library.Schema;
using System;
using System.IO;
using System.Net.Http;
using System.Web;
using System.Web.Mvc;
using System.Xml.Serialization;

namespace Client.Controllers
{
    public class ClientController : Controller
    {
        //Client URLs
        private const string clientBaseAddress = "http://localhost:33222";
        private const string clientOAuthCodeReturnURL = clientBaseAddress + "/Client/OAuthRedirect";

        //SAML server URL
        private const string samlRequestAddress = "http://localhost:33848/SAML/AuthnRequest";

        //Authorisation server URLs
        private const string authorizationServerBaseAddress = "https://localhost:44301";
        private const string authorizationServerSAMLAuthorizeAddress = authorizationServerBaseAddress + "/OAuth/SAMLAuthorize";
        private const string authorizationServerTokenAddress = authorizationServerBaseAddress + "/OAuth/Token";

        //Resource server URL
        private const string resourceAddress = "http://localhost:33367/api/Resource";
        
        /// <summary>
        /// Landing page
        /// </summary>
        public ActionResult Main()
        {
            return View();
        }

        /// <summary>
        /// Attempt to access the resource on the Resource server
        /// </summary>
        public ActionResult GetResource()
        {
            string OAuthToken = "";

            if (Request.Cookies["OAuthToken"] != null)
            {
                OAuthToken = Request.Cookies["OAuthToken"].Value;
            }

            var client = new HttpClient(new OAuthRequestHttpHandler(OAuthToken));

            try
            {
                ViewBag.ApiResponse = client.GetStringAsync(new Uri(resourceAddress)).Result;
            }

            //User is not authorized e.g. invalid/expired OAuthToken
            catch (AggregateException ex)
            {
                if (ex.InnerException != null && ex.InnerException is HttpRequestException)
                {
                    var samlRequest = CreateSAMLRequest();

                    string redirectURL = samlRequestAddress + 
                        "?samlRequest=" + HttpUtility.UrlEncode(samlRequest);

                    return Redirect(redirectURL);
                }
                else
                {
                    return View("Error");
                }
            }

            return View("Main");
        }

        /// <summary>
        /// Receives the OAuth code from the OAuth server and sends back a request for the OAuth token
        /// </summary>
        public ActionResult OAuthRedirect()
        {
            if (Request.Params["code"] != null && Request.Params["state"] != null)
            {
                //Extract the session for the user
                SessionObj sessionObj = (SessionObj) Session[Request.Params["state"]];

                //Request the OAuth token
                var authorizeGetTokenURI = new Uri(authorizationServerTokenAddress);
                var client = new HttpClient(new OAuthCodeHttpHandler(sessionObj.User, 
                    sessionObj.SAMLToken.GetHashCode().ToString())
                    );
                StringContent stringContent = new StringContent(
                    "grant_type=authorization_code" +
                    "&client_id=" + sessionObj.User +
                    "&code=" + Request.Params["code"] +
                    "&redirect_uri=" + HttpUtility.UrlEncode(clientOAuthCodeReturnURL)
                    , System.Text.Encoding.UTF8, "application/x-www-form-urlencoded");
                var result = client.PostAsync(authorizeGetTokenURI, stringContent).Result;

                //Persist OAuth token
                if(result.StatusCode == System.Net.HttpStatusCode.OK)
                {
                    string content = result.Content.ReadAsStringAsync().Result;
                    JObject jobject = JObject.Parse(content);
                    string accessToken = jobject.Value<string>("access_token");
                    Response.Cookies.Add(new HttpCookie("OAuthToken", accessToken)
                    {
                        HttpOnly = true
                    });
                }
            }

            return RedirectToAction("Main");
        }
        
        /// <summary>
        /// Passes the response of the SAML server on to the OAuth server and stores the user state
        /// </summary>
        /// <param name="username">The federated user name agreeded between the SAML server and the OAuth server</param>
        /// <param name="samlResponse">SAML Response XML returned by the server</param>
        [HttpPost]
        public ActionResult AuthnResponse(string username, string samlResponse)
        {
            //Handle response from the SAML server
            if (samlResponse != null)
            {
                //Store user state so we can construct appropriate URL 
                //when requesting the OAuth token after receiving the OAuth code
                SessionObj stateObj = new SessionObj
                {
                    User = username,
                    SAMLToken = samlResponse
                };
                string stateId = Guid.NewGuid().ToString();
                HttpContext.Session.Add(stateId, stateObj);

                //Craft url to request OAuth code
                ViewBag.AuthServerUrl = authorizationServerSAMLAuthorizeAddress +
                    "?redirect_uri=" + clientOAuthCodeReturnURL +
                    "&state=" + stateId +
                    "&scope=photos documents" +
                    "&response_type=code";

                //The encoded SAML Response to be embedded in the form
                ViewBag.SAMLResponse = samlResponse;

                //Redirect to authorisation prompt
                return View("OAuthRedirect");
            }

            return RedirectToAction("Main");
        }
        
        /// <summary>
        /// Creates a SAMLRequest object and serializes it.
        /// </summary>
        /// <returns>The serialized SAMLRequest object</returns>
        private string CreateSAMLRequest()
        {
            AuthnRequestType samlRequest = new AuthnRequestType()
            {
                ID = Guid.NewGuid().ToString(),
                Version = "2.0",
                IssueInstant = DateTime.UtcNow,
                Issuer = new NameIDType
                {
                    Value = clientBaseAddress
                },
                NameIDPolicy = new NameIDPolicyType
                {
                    AllowCreate = true,
                    Format = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
                }
            };

            XmlSerializer serializer = new XmlSerializer(typeof(AuthnRequestType));
            StringWriter writer = new StringWriter();
            serializer.Serialize(writer, samlRequest);

            string base64EncodedRequest = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(writer.ToString()));

            return base64EncodedRequest;
        }
    }
}