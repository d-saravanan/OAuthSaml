using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Client.Utils
{
    /// <summary>
    /// Automatically adds the provided OAuthToken to every request
    /// </summary>
    public class OAuthCodeHttpHandler : HttpClientHandler
    {
        private string username;
        private string samltoken;

        public OAuthCodeHttpHandler(string username, string samltoken)
        {
            this.username = username;
            this.samltoken = samltoken;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string credentials = username + ":" + samltoken;

            request.Headers.Add("Authorization", "Basic " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(credentials)));

            return base.SendAsync(request, cancellationToken);
        }
    }
}