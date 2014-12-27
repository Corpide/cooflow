using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using BNTracker.Models;
using System.Text.RegularExpressions;
using CSharpVitamins;
using Postal;

using System.Text;
using System.Security.Cryptography;



namespace BNTracker.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        public AccountController()
            : this(new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext())))
        {
            UserManager.UserValidator = new CustomUserValidator<ApplicationUser>(UserManager);
        }

        public AccountController(UserManager<ApplicationUser> userManager)
        {
            UserManager = userManager;
        }

        public UserManager<ApplicationUser> UserManager { get; private set; }


        
        private string CreateConfirmationToken()
        {
            return ShortGuid.NewGuid();
        }

        private void SendEmailConfirmation(string to, string username, string confirmationToken,string subject)
        {
            dynamic email = new Email("RegEmail");
            email.To = to;
            
            email.UserName = username;
            email.ConfirmationToken = confirmationToken;
            email.Subject = subject;
            email.Send();
        }

        //
        // GET: /Account/BeforePasswordReset
        [AllowAnonymous]
        public ActionResult ForgotPassword()
        {
            return View();
        }

        //
        // POST: /Account/BeforePasswordReset

      
        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public  ActionResult ForgotPassword(BeforePasswordResetViewModel model)
        {
            string message = null;

            var db = new ApplicationDbContext();
            var user = db.UserInfoes.FirstOrDefault(x => x.Email == model.Email);

            if (null != user)
            {
                 
                var tokenid = CreateConfirmationToken();
               // user.Manager = 3;
                
                //Generating a token
              
                 //userManager.RemovePassword(userId);

                // userManager.AddPassword(userId, newPassword);


                user.ConfirmationToken = tokenid;
             

                if (db.SaveChanges()>0)
                {
                    tokenid = GetBaseUrl() +
                        "Account/PasswordReset?digest=" + tokenid;

                    SendEmailConfirmation(model.Email, model.UserName, tokenid, "BNTracker Reset Password");
                    message = "We have sent a password reset request if the email is verified.";
                    return RedirectToAction("PasswordResetReq", new { token = string.Empty, message = message });
                }
            }
            return View();

        }
        public string GetBaseUrl()
        {
            var request = HttpContext.Request;
            var appUrl = HttpRuntime.AppDomainAppVirtualPath;

            if (!string.IsNullOrWhiteSpace(appUrl)) appUrl += "";

            var baseUrl = string.Format("{0}://{1}{2}", request.Url.Scheme, request.Url.Authority, appUrl);

            return baseUrl;
        }
        //
        // GET: /Account/PasswordReset
        [AllowAnonymous]
        public ActionResult PasswordResetReq(string message)
        {
            ViewBag.StatusMessage = message ?? "";
            return View();
        }
        [AllowAnonymous]
        public ActionResult PasswordReset(string digest)
        {
            string message = null;
            BNTracker.Models.PasswordResetViewModel model = new BNTracker.Models.PasswordResetViewModel() ;
            model.Token = digest;
            var db = new ApplicationDbContext();
            var user = db.UserInfoes.FirstOrDefault(x => x.ConfirmationToken == digest);

            if (null != user)
            {

                var UserName = user.EmployeeCode;
                UserManager.FindByName(UserName);
               
                
            }
            return View(model);
        }

        //
        // POST: /Account/PasswordReset
        [AllowAnonymous]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public  ActionResult PasswordReset(PasswordResetViewModel model)
        {
            if (ModelState.IsValid)
            {
                   string message = null;

                   var db = new ApplicationDbContext();
                    var user = db.UserInfoes. FirstOrDefault(x => x.ConfirmationToken  == model.Token  );

                    if (null != user)
                    {
                        var result= UserManager.RemovePassword( UserManager.FindByName(user.EmployeeCode).Id);
                        if (result.Succeeded)
                            {
                                result= UserManager.AddPassword( UserManager.FindByName(user.EmployeeCode).Id,model.NewPassword );
                                if (result.Succeeded)
                                {
                                    user.ConfirmationToken ="";
                                    if (db.SaveChanges() > 0)
                                    {
                                        message = "The password has been reset.";
                                        return RedirectToAction("PasswordResetCompleted", new { message = message });
                                    }
                                    else
                                        ModelState.AddModelError("", "Error while resetting token");

                                }
                                    else
                                    {
                                        AddErrors(result);
                                    }           
                            }
                            else
                            {
                                AddErrors(result);
                            }
                       }
                        //reset the password
                
              
            }
            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // GET: /Account/PasswordResetCompleted
        [AllowAnonymous]
        public ActionResult PasswordResetCompleted(string message)
        {
            ViewBag.StatusMessage = message ?? "";
            return View();
        }
        //
        // GET: /Account/Login
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl)
        {
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindAsync(model.UserName, model.Password);
                if (user != null)
                {
                    await SignInAsync(user, model.RememberMe);


                   // SetUserNameSession(model.UserName);
                    return RedirectToLocal(returnUrl);
                }
                else
                {
                    ModelState.AddModelError("", "Invalid username or password.");
                    
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        private string GetUserNameSession(string UserName)
        {
            


        var currentUserId = User.Identity.GetUserId();
        //Instantiate the UserManager in ASP.Identity system so you can look up the user in the system 
        var manager = new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext()));
        //Get the User object 
        var currentUser = manager.FindById(User.Identity.GetUserId());
        // Get the profile information about the user 
        var s = currentUser.UserInfo.FirstName;
           
        return s;
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()

        {
            SetLineManagerDropDown();
            return View();
        }

        private void SetLineManagerDropDown()
        {
            var db = new ApplicationDbContext();
            //To display First Name and Last name anonymus class used.
            var stands =
                  db.UserInfoes
                //  .Where(s => s.ExhibitorID == null)
                    .ToList()
                    .Select(s => new
                    {
                        Id = s.Id,
                        Description = string.Format("{0} {1}", s.FirstName, s.LastName)
                    });

            ViewBag.Manager = new SelectList(stands, "Id", "Description");

            // ViewBag.Manager = new SelectList(db.UserInfoes,"Id","FirstName");
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                string confirmationToken = CreateConfirmationToken();
                var user = new ApplicationUser()
                {
                    UserName = model.UserName
                };



                SetProfileInfo(model, user);

                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {

                    //if (UpdateUserInfo(model))
                    //{
                    await SignInAsync(user, isPersistent: false);
                   // SetUserNameSession(model.UserName);
                    SendEmailConfirmation(model.Email, model.UserName, confirmationToken,"BNTracker Registration");
                    //}
                    //else
                    //ModelState.AddModelError(string.Empty, "Update Failed");
                    
                    // All good then
             
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    AddErrors(result);
                }
            }

            // If we got this far, something failed, redisplay form
            SetLineManagerDropDown();
            return View(model);
        }

        private void SetProfileInfo(RegisterViewModel model,  ApplicationUser usr)
        {

            usr.UserInfo = new UserProfile();

                usr.UserInfo.EmployeeCode   = model.UserName;
                usr.UserInfo.FirstName      = model.FirstName;
                usr.UserInfo.LastName       = model.LastName;
                usr.UserInfo.Manager        = model.Manager;
                usr.UserInfo.Email          = model.Email;
                usr.UserInfo.IsManagerConfirmed = false;
                usr.UserInfo.IsUserConfirmed=false;
            
        }

        //
        // POST: /Account/Disassociate
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Disassociate(string loginProvider, string providerKey)
        {
            ManageMessageId? message = null;
            IdentityResult result = await UserManager.RemoveLoginAsync(User.Identity.GetUserId(), new UserLoginInfo(loginProvider, providerKey));
            if (result.Succeeded)
            {
                message = ManageMessageId.RemoveLoginSuccess;
            }
            else
            {
                message = ManageMessageId.Error;
            }
            return RedirectToAction("Manage", new { Message = message });
        }

        //
        // GET: /Account/Manage
        public ActionResult Manage(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.ChangePasswordSuccess ? "Your password has been changed."
                : message == ManageMessageId.SetPasswordSuccess ? "Your password has been set."
                : message == ManageMessageId.RemoveLoginSuccess ? "The external login was removed."
                : message == ManageMessageId.Error ? "An error has occurred."
                : "";
            ViewBag.HasLocalPassword = HasPassword();
            ViewBag.ReturnUrl = Url.Action("Manage");
            return View();
        }

        //
        // POST: /Account/Manage
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Manage(ManageUserViewModel model)
        {
            bool hasPassword = HasPassword();
            ViewBag.HasLocalPassword = hasPassword;
            ViewBag.ReturnUrl = Url.Action("Manage");
            if (hasPassword)
            {
                if (ModelState.IsValid)
                {
                    IdentityResult result = await UserManager.ChangePasswordAsync(User.Identity.GetUserId(), model.OldPassword, model.NewPassword);
                    if (result.Succeeded)
                    {
                        return RedirectToAction("Manage", new { Message = ManageMessageId.ChangePasswordSuccess });
                    }
                    else
                    {
                        AddErrors(result);
                    }
                }
            }
            else
            {
                // User does not have a password so remove any validation errors caused by a missing OldPassword field
                ModelState state = ModelState["OldPassword"];
                if (state != null)
                {
                    state.Errors.Clear();
                }

                if (ModelState.IsValid)
                {
                    IdentityResult result = await UserManager.AddPasswordAsync(User.Identity.GetUserId(), model.NewPassword);
                    if (result.Succeeded)
                    {
                        return RedirectToAction("Manage", new { Message = ManageMessageId.SetPasswordSuccess });
                    }
                    else
                    {
                        AddErrors(result);
                    }
                }
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        //
        // POST: /Account/ExternalLogin
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLogin(string provider, string returnUrl)
        {
            // Request a redirect to the external login provider
            return new ChallengeResult(provider, Url.Action("ExternalLoginCallback", "Account", new { ReturnUrl = returnUrl }));
        }

        //
        // GET: /Account/ExternalLoginCallback
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync();
            if (loginInfo == null)
            {
                return RedirectToAction("Login");
            }

            // Sign in the user with this external login provider if the user already has a login
            var user = await UserManager.FindAsync(loginInfo.Login);
            if (user != null)
            {
                await SignInAsync(user, isPersistent: false);
                return RedirectToLocal(returnUrl);
            }
            else
            {
                // If the user does not have an account, then prompt the user to create an account
                ViewBag.ReturnUrl = returnUrl;
                ViewBag.LoginProvider = loginInfo.Login.LoginProvider;
                return View("ExternalLoginConfirmation", new ExternalLoginConfirmationViewModel { UserName = loginInfo.DefaultUserName });
            }
        }

        //
        // POST: /Account/LinkLogin
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LinkLogin(string provider)
        {
            // Request a redirect to the external login provider to link a login for the current user
            return new ChallengeResult(provider, Url.Action("LinkLoginCallback", "Account"), User.Identity.GetUserId());
        }

        //
        // GET: /Account/LinkLoginCallback
        public async Task<ActionResult> LinkLoginCallback()
        {
            var loginInfo = await AuthenticationManager.GetExternalLoginInfoAsync(XsrfKey, User.Identity.GetUserId());
            if (loginInfo == null)
            {
                return RedirectToAction("Manage", new { Message = ManageMessageId.Error });
            }
            var result = await UserManager.AddLoginAsync(User.Identity.GetUserId(), loginInfo.Login);
            if (result.Succeeded)
            {
                return RedirectToAction("Manage");
            }
            return RedirectToAction("Manage", new { Message = ManageMessageId.Error });
        }

        //
        // POST: /Account/ExternalLoginConfirmation
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl)
        {
            if (User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Manage");
            }

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await AuthenticationManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    return View("ExternalLoginFailure");
                }
                var user = new ApplicationUser() { UserName = model.UserName };
                var result = await UserManager.CreateAsync(user);
                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user.Id, info.Login);
                    if (result.Succeeded)
                    {
                        await SignInAsync(user, isPersistent: false);
                        return RedirectToLocal(returnUrl);
                    }
                }
                AddErrors(result);
            }

            ViewBag.ReturnUrl = returnUrl;
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            AuthenticationManager.SignOut();
            return RedirectToAction("Index", "Home");
        }

        //
        // GET: /Account/ExternalLoginFailure
        [AllowAnonymous]
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }

        [ChildActionOnly]
        public ActionResult RemoveAccountList()
        {
            var linkedAccounts = UserManager.GetLogins(User.Identity.GetUserId());
            ViewBag.ShowRemoveButton = HasPassword() || linkedAccounts.Count > 1;
            return (ActionResult)PartialView("_RemoveAccountPartial", linkedAccounts);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && UserManager != null)
            {
                UserManager.Dispose();
                UserManager = null;
            }
            base.Dispose(disposing);
        }

        #region Helpers
        // Used for XSRF protection when adding external logins
        private const string XsrfKey = "XsrfId";

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        private async Task SignInAsync(ApplicationUser user, bool isPersistent)
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
            var identity = await UserManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
            AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = isPersistent }, identity);
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private bool HasPassword()
        {
            var user = UserManager.FindById(User.Identity.GetUserId());
            if (user != null)
            {
                return user.PasswordHash != null;
            }
            return false;
        }

        public enum ManageMessageId
        {
            ChangePasswordSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            Error
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        private class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }

            public override void ExecuteResult(ControllerContext context)
            {
                var properties = new AuthenticationProperties() { RedirectUri = RedirectUri };
                if (UserId != null)
                {
                    properties.Dictionary[XsrfKey] = UserId;
                }
                context.HttpContext.GetOwinContext().Authentication.Challenge(properties, LoginProvider);
            }
        }
        #endregion
    }



    /// <summary>
    /// A replacement for the <see cref="UserValidator"/> which requires that an email 
    /// address be used for the <see cref="IUser.UserName"/> field.
    /// </summary>
    /// <typeparam name="TUser">Must be a type derived from <see cref="Microsoft.AspNet.Identity.IUser"/>.</typeparam>
    /// <remarks>
    /// This validator check the <see cref="IUser.UserName"/> property against the simple email regex provided at
    /// http://www.regular-expressions.info/email.html. If a <see cref="UserManager"/> is provided in the constructor,
    /// it will also ensure that the email address is not already being used by another account in the manager.
    /// 
    /// To use this validator, just set <see cref="UserManager.UserValidator"/> to a new instance of this class.
    /// </remarks>
    public class CustomUserValidator<TUser> : IIdentityValidator<TUser>
        where TUser : class, Microsoft.AspNet.Identity.IUser
    {
       // private static readonly Regex EmailRegex = new Regex(@"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4}$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        private readonly UserManager<TUser> _manager;

        public CustomUserValidator()
        {
        }

        public CustomUserValidator(UserManager<TUser> manager)
        {
            _manager = manager;
        }

        public async Task<IdentityResult> ValidateAsync(TUser item)
        {
            var errors = new List<string>();
            //if (!EmailRegex.IsMatch(item.UserName))
            //    errors.Add("Enter a valid email address.");

            if (_manager != null)
            {
                var otherAccount = await _manager.FindByNameAsync(item.UserName);
                if (otherAccount != null && otherAccount.Id != item.Id)
                    errors.Add("Select a different Employee Code. An account has already been created with " + item.UserName);
            }

            return errors.Any()
                ? IdentityResult.Failed(errors.ToArray())
                : IdentityResult.Success;
        }
    }



}