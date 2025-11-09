using cmsAuth.Application.DTO;
using cmsAuth.Application.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace cmsAuth.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IAuthenticationService _authenticationService;
    
    public AuthController(IAuthenticationService authenticationService)
    {
        _authenticationService = authenticationService;
    }
    
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterUser user)
    {
        var result = await _authenticationService.Register(user);
        return Ok(result);
    }
    
    [HttpGet("login")]
    public IActionResult Login(string email, string password)
    {
        var user = _authenticationService.Login(email, password);
        return Ok(user);
    }
}
