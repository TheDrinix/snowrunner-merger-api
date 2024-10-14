using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Models.Auth.Dtos;
using SnowrunnerMergerApi.Services;

namespace SnowrunnerMergerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class UserController(IUserService userService) : ControllerBase
    {
        [HttpGet]
        public async Task<ActionResult<User>> GetCurrentUser()
        {
            var user = await userService.GetCurrentUser();

            return Ok(user);
        }

        [HttpPatch]
        public async Task<ActionResult<User>> UpdateUsername(UpdateUsernameDto data)
        {
            var updatedUser = await userService.UpdateUsername(data.Username);

            return Ok(updatedUser);
        }

        [HttpDelete]
        public async Task<ActionResult> DeleteAccount()
        {
            await userService.DeleteUser();

            return NoContent();
        }
    }
}
