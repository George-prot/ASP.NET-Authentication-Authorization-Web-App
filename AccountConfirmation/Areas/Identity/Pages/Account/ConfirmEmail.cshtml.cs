// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.CodeAnalysis.Elfie.Diagnostics;

namespace AccountConfirmation.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class ConfirmEmailModel : PageModel
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILogger<ConfirmEmailModel> _logger; // Add logger

        public ConfirmEmailModel(UserManager<IdentityUser> userManager, ILogger<ConfirmEmailModel> logger)
        {
            _logger = logger; // Inject logger
            _userManager = userManager;
        }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [TempData]
        public string StatusMessage { get; set; }
        public async Task<IActionResult> OnGetAsync(string userId, string code)
        {
            if (userId == null || code == null)
            {
                _logger.LogWarning("Missing userId or code in confirmation URL.");
                return RedirectToPage("/Index");
            }

            _logger.LogInformation($"userId: {userId}, encoded code: {code}");
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning($"Unable to load user with ID '{userId}'."); // Log warning
                return NotFound($"Unable to load user with ID '{userId}'.");
            }

            //user.EmailConfirmed = true;// Print the original and decoded tokens for debugging
            //_logger.LogInformation("Encoded token: " + code);
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            //_logger.LogInformation("Decoded token: " + code);
            _logger.LogInformation($"Decoded token: {code}");
            var result = await _userManager.ConfirmEmailAsync(user, code);
            if (result.Succeeded)
            {
                _logger.LogInformation($"Email confirmed for user: {user.Email}"); // Log success
                StatusMessage = "Thank you for confirming your email.";
            }
            else
            {
                _logger.LogError("Email confirmation failed: " + result.Errors.FirstOrDefault()?.Description); // Log error
                StatusMessage = "Error confirming your email.";
            }

            return Page();
            StatusMessage = result.Succeeded ? "Thank you for confirming your email." : "Error confirming your email.";
            return Page();
        }
    }
}
