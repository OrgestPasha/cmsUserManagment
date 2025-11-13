using cmsUserManagment.Application.DTO;
using cmsUserManagment.Application.Interfaces;
using cmsUserManagment.Infrastructure.Security;

using Google.Authenticator;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace cmsUserManagment.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize]
public class AuthController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    private readonly HeadersManager _headersManager;
    private readonly IJwtTokenProvider _jwtTokenProvider;

    public AuthController(IAuthenticationService authenticationService, IJwtTokenProvider jwtTokenProvider,
        HeadersManager headersManager)
    {
        _authenticationService = authenticationService;
        _jwtTokenProvider = jwtTokenProvider;
        _headersManager = headersManager;
    }

    [HttpPost("register")]
    [AllowAnonymous]
    public async Task<IActionResult> Register([FromBody] RegisterUser newUser)
    {
        bool result = await _authenticationService.Register(newUser);
        return Ok(result);
    }


    [HttpGet("login")]
    [AllowAnonymous]
    public async Task<IActionResult> Login(string email, string password)
    {
        var tokens = await _authenticationService.Login(email, password);
        return Ok(tokens);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] Guid refreshToken)
    {
        string jwt = _headersManager.GetJwtFromHeader(Request.Headers);
        try
        {
            await _authenticationService.Logout(jwt, refreshToken);
            return Ok();
        }
        catch (Exception e)
        {
            return BadRequest("There was an error while logging out.");
        }
    }

    [HttpGet("refresh-token")]
    public async Task<IActionResult> RefreshToken(Guid refreshToken)
    {
        var token = await _authenticationService.RefreshToken(refreshToken, _headersManager.GetJwtFromHeader(Request.Headers));
        return Ok(token);
    }





    // [HttpGet("two-factor-auth")]
    // public IActionResult GetTwoFactorAuthSetupInfo([FromBody] TwoFactorCodeInput credentials)
    // {
    //     string token = _authenticationService.twoFactorAuthentication(credentials.loginId, credentials.code);
    //     return Ok(token);
    // }


    //
    // [HttpGet("testing")]
    // public IActionResult Testing(string manualKey)
    // {
    //     string key = "teest";
    //     TwoFactorAuthenticator tfa = new TwoFactorAuthenticator();
    //     bool result = tfa.ValidateTwoFactorPIN(key, manualKey);
    //
    //     if (!result) return BadRequest("not working");
    //     return Ok("it works");
    // }
    //
    // [HttpGet("testing-the-authmiddleware")]
    // [Authorize]
    // public IActionResult TestingTheAuthMiddleware()
    // {
    //     return Ok("it works");
    // }
}
