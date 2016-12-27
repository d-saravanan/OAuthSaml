using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web.Http;

namespace ResourceServer.Controllers
{
    [Authorize]
    public class ResourceController : ApiController
    {
        // GET api/<controller>
        public string Get()
        {
            var identity = User.Identity as ClaimsIdentity;           

            string result = "User with following claims accessed the resource: \n";
            
            foreach(var claim in identity.Claims)
            {
                result = result + claim.Type + " " + claim.Value + "\n";
            }

            return result;
        }
    }
}
