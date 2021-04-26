using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Saml2WebApp.Controllers
{
    public class AccountController : Controller
    {
        private readonly ILogger<AccountController> _logger;
        public AccountController(ILogger<AccountController> logger)
        {
            _logger = logger;
        }
        [Authorize]
        public IActionResult Claims()
        {
            ViewData["Message"] = string.Format("Claims available for the user {0}", (User.FindFirst("name")?.Value));
            return View();
        }

        [HttpGet]
        public IActionResult SignIn()
        {
            _logger.LogInformation("SignIn()");
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Url.Action(nameof(HomeController.Index), "Home")
            }, Sustainsys.Saml2.AspNetCore2.Saml2Defaults.Scheme);
        }

        [Authorize]
        [HttpGet]
        public IActionResult SignOut()
        {
            _logger.LogInformation("SignOut()");
            var authProps = new AuthenticationProperties
            {
                RedirectUri = Url.Action(nameof(Index), "Home", values: null, protocol: Request.Scheme)
            };
            // you need these two in order for Sustainsys.Saml2 to successfully sign out
            AddAuthenticationPropertiesClaim(authProps, "/SessionIndex");
            AddAuthenticationPropertiesClaim(authProps, "/LogoutNameIdentifier");
            return SignOut(authProps, CookieAuthenticationDefaults.AuthenticationScheme, Sustainsys.Saml2.AspNetCore2.Saml2Defaults.Scheme);
        }
        private void AddAuthenticationPropertiesClaim(AuthenticationProperties authProps, string name)
        {
            string claimValue = GetClaimValue(name, out string claimName);
            if (!string.IsNullOrEmpty(claimValue))
                authProps.Items[claimName] = claimValue;
        }
        private string GetClaimValue(string name, out string fullName)
        {
            fullName = null;
            name = name.ToLowerInvariant();
            foreach (Claim claim in User.Claims) {
                if (claim.Type.ToLowerInvariant().Contains(name))  {
                    fullName = claim.Type;
                    return claim.Value;
                }
            }
            return null;
        }
    } // cls
} // ns
