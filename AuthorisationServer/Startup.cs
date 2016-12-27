using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(AuthorisationServer.Startup))]
namespace AuthorisationServer
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
