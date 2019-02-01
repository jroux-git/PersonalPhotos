using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PersonalPhotos.Interfaces;
using PersonalPhotos.Models;

namespace PersonalPhotos.Controllers
{
    public class LoginsController : Controller
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly ILogins _loginService;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmail _email;

        public LoginsController(ILogins loginService, IHttpContextAccessor httpContextAccessor, UserManager<IdentityUser> userManager, 
            SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager, IEmail email)
        {
            _loginService = loginService;
            _httpContextAccessor = httpContextAccessor;
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _email = email;
        }

        public IActionResult Index(string returnUrl = null)
        {
            var model = new LoginViewModel { ReturnUrl = returnUrl};
            return View("Login", model);
        }

        [HttpPost]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Invalid login detils");
                return View("Login", model);
            }

            // Check if user exist by email and have confirmed with token
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null || !user.EmailConfirmed)
            {
                ModelState.AddModelError("", "Usernot found or email was not confirmed");
            }

            // Passoword SignIn
            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);

            if (!result.Succeeded)
            {
                if (result == Microsoft.AspNetCore.Identity.SignInResult.TwoFactorRequired)
                {
                    return RedirectToAction("MfaLogin");
                }

                ModelState.AddModelError("", "Username and/or Password is incorrect");
                return View();
            }

            // Add claims
            var claims = new List<Claim>();
            claims.Add(new Claim("Over18Claim", "True"));
            User.AddIdentity(new ClaimsIdentity(claims));

            // Redirect after login
            if (!string.IsNullOrEmpty(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }
            else
            {
                return RedirectToAction("Display", "Photos");
            }
        }

        public IActionResult Create()
        {
            return View("Create");
        }

        [HttpPost]
        public async Task<IActionResult> Create(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Invalid user details");
                return View(model);
            }

            if (!await _roleManager.RoleExistsAsync("Editor"))
            {
                await _roleManager.CreateAsync(new IdentityRole("Editor"));
            }

            var user  = new IdentityUser{
                UserName = model.Email,
                Email = model.Email
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, $"{error.Code}:{error.Description}");
                }
            }

            //await _userManager.AddToRoleAsync(user, "Editor");
            var token = _userManager.GenerateEmailConfirmationTokenAsync(user);
            var url = Url.Action("Confirmation", "Logins", new { userId=user.Id, token=token}, HttpContext.Request.Scheme);
            var emailBody = $"Please confirm you email by clicking on the link below <br /> {url}";
            await _email.Send(model.Email, emailBody);

            return RedirectToAction("Index", "Logins");
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {

            await _signInManager.SignOutAsync();

            return RedirectToAction("Index","Logins");
        }

        public async Task<IActionResult> Confirmation(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            var confirm = await _userManager.ConfirmEmailAsync(user, token);

            if (confirm.Succeeded)
            {
                var is2FaEnabled = await _userManager.GetTwoFactorEnabledAsync(user);

                if (!is2FaEnabled)
                {
                    return RedirectToAction("Setup2Fa");
                }

                return RedirectToAction("Index", "Login");
            }

            ViewBag["Error"] = "Error validating email address";
            return View();
        }

        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Invalid user details");
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.EmailAddress);
            if (user != null || user.EmailConfirmed)
            {
                var token = _userManager.GeneratePasswordResetTokenAsync(user);
                var url = Url.Action("ChangePassword", "Logins", new { userId = user.Id, token = token }, HttpContext.Request.Scheme);
                var emailBody = $"Click on link to reset your password: <br /> {url}";
                await _email.Send(model.EmailAddress, emailBody);
            }

            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ChangePassword(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                var model = new ChangePasswordViewModel()
                {
                    EmailAddress = user.Email,
                    Token = token
                };

                return View(model);
            }

            return View();
        }

        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Invalid user details");
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.EmailAddress);
            if (user != null)
            {
                var resetPasswordResult =_userManager.ResetPasswordAsync(user, model.Token, model.Passsword);

                return RedirectToAction("Index");
            }

            ModelState.AddModelError("", "Invalid user details");
            return View(model);
        }

        public async Task<IActionResult> Setup2Fa()
        {
            var user = await _userManager.GetUserAsync(User);

            if (user != null)
            {
                var authKey = await _userManager.GetAuthenticatorKeyAsync(user);

                if (string.IsNullOrEmpty(authKey))
                {
                    await _userManager.ResetAuthenticatorKeyAsync(user);
                    authKey = await _userManager.GetAuthenticatorKeyAsync(user);
                }

                var model = new MfaCreateViewModel()
                {
                    //AuthKey = FormatAuthKey(authKey)
                    AuthKey = authKey
                };

                return View(model);
            }

            return View();
        }

        [Authorize]
        [HttpPost]
        public async Task<IActionResult> Setup2Fa(MfaCreateViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);

            var isTokenCorrect = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);

            if (!isTokenCorrect)
            {
                ModelState.AddModelError("", "The code did not match the authkey!");
                
                return View(model);
            }

            // enable 2FA for a user after successful validation
            await _userManager.SetTwoFactorEnabledAsync(user, true);

            return RedirectToAction("Index", "Logins");
        }

        [Authorize]
        private string FormatAuthKey(string authKey)
        {
            const int chunkLen = 5;
            var sb = new StringBuilder();

            while (authKey.Length > 0)
            {
                var len = chunkLen > authKey.Length ? authKey.Length : chunkLen;
                sb.Append(authKey.Substring(0, len));
                authKey = authKey.Remove(0, len);
            }

            return sb.ToString();
        }

        public async Task<IActionResult> MfaLogin()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> MfaLogin(MfaLoginViewModel model)
        { 
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.TwoFactorSignInAsync(_userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code, true, true);

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Your code could not be validated, please try again");
                return View(model);
            }

            return RedirectToAction("Index", "Logins");
        }

        [HttpPost]
        public async Task<IActionResult> ExternalLogin(string provider, string returnUrl)
        {
            var redirectUrl = Url.Action("ExternalLoginCallback", "Logins", new { returnUrl });
            var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);

            return Challenge(properties, provider);
        }

        public async Task<IActionResult> ExternalLoginCallback(string returnUrl=null, string remoteError=null)
        {
            if (remoteError != null)
            {
                return RedirectToAction("Index");
            }
            
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info != null)
            {
                return RedirectToAction("Index");
            }

            var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, true, true);

            if (result.Succeeded)
            {
                return RedirectToAction("Index", "Home");
            }

            return View();
        }
    }
}