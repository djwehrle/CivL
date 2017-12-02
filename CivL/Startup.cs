using Microsoft.Owin;
using Owin;

[assembly: OwinStartup(typeof(CivL.Startup))]
namespace CivL
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}