using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(OtopakSistemi.Startup))]
namespace OtopakSistemi
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
