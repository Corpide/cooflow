using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(BNTracker.Startup))]
namespace BNTracker
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
