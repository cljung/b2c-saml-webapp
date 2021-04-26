using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Saml2WebApp
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // we need to associate SHA1/SHA256 with the long web-based names for Sustainsys.Saml2 to work
            System.Security.Cryptography.CryptoConfig.AddAlgorithm(typeof(RsaPkCs1Sha256SignatureDescription), System.Security.Cryptography.Xml.SignedXml.XmlDsigRSASHA256Url);
            System.Security.Cryptography.CryptoConfig.AddAlgorithm(typeof(RsaPkCs1Sha1SignatureDescription), System.Security.Cryptography.Xml.SignedXml.XmlDsigRSASHA1Url);

            services.AddAuthentication(sharedOptions =>
            {
                sharedOptions.DefaultScheme = Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultSignInScheme = Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultChallengeScheme = Sustainsys.Saml2.AspNetCore2.Saml2Defaults.Scheme;
            })
            .AddSaml2(options =>
            {
                options.SPOptions = new Sustainsys.Saml2.Configuration.SPOptions()
                {
                    AuthenticateRequestSigningBehavior = Sustainsys.Saml2.Configuration.SigningBehavior.Never,
                    EntityId = new Sustainsys.Saml2.Metadata.EntityId(Configuration.GetValue<string>("Saml2:EntityId")),
                    MinIncomingSigningAlgorithm = Configuration.GetValue<string>("Saml2:MinIncomingSigningAlgorithm")
                };

                // We need to use a cert for Sustainsys.Saml2 to work with logout, so we borrow their sample cert
                // https://github.com/Sustainsys/Saml2/blob/develop/Samples/SampleAspNetCore2ApplicationNETFramework/Sustainsys.Saml2.Tests.pfx
                string certFile = string.Format("{0}\\{1}", System.IO.Directory.GetCurrentDirectory(), Configuration.GetValue<string>("Saml2:cert"));
                options.SPOptions.ServiceCertificates.Add(new System.Security.Cryptography.X509Certificates.X509Certificate2(certFile));

                // The Azure AD B2C Identity Provider we use
                options.IdentityProviders.Add(
                  new Sustainsys.Saml2.IdentityProvider(
                    new Sustainsys.Saml2.Metadata.EntityId(Configuration.GetValue<string>("Saml2:IdpEntityId")), options.SPOptions)
                  {
                      MetadataLocation = Configuration.GetValue<string>("Saml2:IdpMetadata"),
                      LoadMetadata = true
                  });
            })
            .AddCookie();

            services.AddControllersWithViews(options =>
            {
                var policy = new AuthorizationPolicyBuilder()
                    .RequireAuthenticatedUser()
                    .Build();
                options.Filters.Add(new AuthorizeFilter(policy));
            });
            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
                endpoints.MapRazorPages();
            });
        }
    } // cls
    public class RsaPkCs1Sha256SignatureDescription : System.Security.Cryptography.SignatureDescription
    {
        public RsaPkCs1Sha256SignatureDescription()
        {
            KeyAlgorithm = "System.Security.Cryptography.RSACryptoServiceProvider";
            DigestAlgorithm = "System.Security.Cryptography.SHA256Managed";
            FormatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureFormatter";
            DeformatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureDeformatter";
        }
        public override System.Security.Cryptography.AsymmetricSignatureDeformatter CreateDeformatter(System.Security.Cryptography.AsymmetricAlgorithm key)
        {
            var asymmetricSignatureDeformatter = (System.Security.Cryptography.AsymmetricSignatureDeformatter)System.Security.Cryptography.CryptoConfig.CreateFromName(DeformatterAlgorithm);
            asymmetricSignatureDeformatter.SetKey(key);
            asymmetricSignatureDeformatter.SetHashAlgorithm("SHA256");
            return asymmetricSignatureDeformatter;
        }
    }
    public class RsaPkCs1Sha1SignatureDescription : System.Security.Cryptography.SignatureDescription
    {
        public RsaPkCs1Sha1SignatureDescription()
        {
            KeyAlgorithm = "System.Security.Cryptography.RSACryptoServiceProvider";
            DigestAlgorithm = "System.Security.Cryptography.SHA1Managed";
            FormatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureFormatter";
            DeformatterAlgorithm = "System.Security.Cryptography.RSAPKCS1SignatureDeformatter";
        }
        public override System.Security.Cryptography.AsymmetricSignatureDeformatter CreateDeformatter(System.Security.Cryptography.AsymmetricAlgorithm key)
        {
            var asymmetricSignatureDeformatter = (System.Security.Cryptography.AsymmetricSignatureDeformatter)System.Security.Cryptography.CryptoConfig.CreateFromName(DeformatterAlgorithm);
            asymmetricSignatureDeformatter.SetKey(key);
            asymmetricSignatureDeformatter.SetHashAlgorithm("SHA1");
            return asymmetricSignatureDeformatter;
        }
    }

} // ns
