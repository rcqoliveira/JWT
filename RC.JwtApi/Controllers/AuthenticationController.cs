using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RC.JwtApi.Shared;

namespace RC.JwtApi.Controllers
{
    [ApiController]
    [Route("v1/authentication")]
    public class AuthenticationController : ControllerBase
    {
        [HttpGet]
        public string Get(string userName, string password)
        {

            if (userName == "admin")
            {
                return AuthenticationConfig.GenerateJSONWebToken(userName);
            }
            else
            {
                return "userName and password is invalid!";
            }
        }

        [Authorize]
        [HttpPost]
        public string Post()
        {
            return "True";
        }
    }
}
