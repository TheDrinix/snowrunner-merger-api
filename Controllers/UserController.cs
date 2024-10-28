using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SnowrunnerMergerApi.Models.Auth;
using SnowrunnerMergerApi.Models.Auth.Dtos;
using SnowrunnerMergerApi.Services;
using SnowrunnerMergerApi.Services.Interfaces;

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

        [HttpPatch("password")]
        public async Task<ActionResult<User>> UpdatePassword(UpdatePasswordDto data)
        {
            var updatedUser = await userService.UpdatePassword(data);

            return Ok(updatedUser);
        }
        
        [HttpPatch("username")]
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
