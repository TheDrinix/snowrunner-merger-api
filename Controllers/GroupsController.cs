using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SnowrunnerMergerApi.Models.Auth.Dtos;
using SnowrunnerMergerApi.Models.Saves;
using SnowrunnerMergerApi.Models.Saves.Dtos;
using SnowrunnerMergerApi.Services;

namespace SnowrunnerMergerApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize] 
    public class GroupsController(
        IAuthService authService, 
        IGroupsService groupsService,
        ISavesService savesService,
        IMapper mapper) : ControllerBase
    {
        [HttpGet]
        public async Task<ActionResult<ICollection<GroupDto>>> GetGroups()
        {
            var sessionData = authService.GetUserSessionData();

            var groups = await groupsService.GetUserGroups(sessionData.Id);
            
            return Ok(mapper.Map<ICollection<GroupDto>>(groups));
        }
        
        [HttpGet("{groupId}")]
        public async Task<ActionResult<GroupDto>> GetGroup(Guid groupId)
        {
            var sessionData = authService.GetUserSessionData();
            
            var group = await groupsService.GetGroupData(groupId, sessionData.Id);
            
            if (group is null) return NotFound();
            
            return Ok(mapper.Map<GroupDto>(group));
        }
        
        [HttpPost]
        public async Task<ActionResult<SaveGroup>> CreateGroup([FromBody] CreateGroupDto data)
        {
            var sessionData = authService.GetUserSessionData();
            
            var group = await groupsService.CreateGroup(data.Name, sessionData.Id);
            
            return Ok(group);
        }
        
        [HttpPost("{groupId:guid}/join")]
        public async Task<ActionResult<GroupDto>> JoinGroup(Guid groupId)
        {
            var sessionData = authService.GetUserSessionData();
            
            var group = await groupsService.JoinGroup(groupId, sessionData.Id);
            
            return Ok(mapper.Map<GroupDto>(group));
        }
        
        [HttpPost("{groupId:guid}/leave")]
        public async Task<IActionResult> LeaveGroup(Guid groupId)
        {
            await groupsService.LeaveGroup(groupId);
            
            return NoContent();
        }

        [HttpPost("{groupId:guid}/upload")]
        public async Task<IActionResult> UploadSave([FromRoute] Guid groupId, [FromForm] UploadSaveDto data)
        {
            if (data.Save.Length > SavesService.MaxSaveSize) return BadRequest();
            
            var save = await savesService.StoreSave(groupId, data);
            
            return Ok(save);
        }

        [HttpPost("{groupid:guid}/merge")]
        public async Task<IActionResult> MergeSaves([FromRoute] Guid groupId, [FromForm] MergeSavesDto data, [FromQuery] int storedSaveNumber = 0)
        {
            var saveZipPath = await savesService.MergeSaves(groupId, data, storedSaveNumber);

            var fs = new FileStream(saveZipPath, FileMode.Open, FileAccess.Read, FileShare.None, 4096,
                FileOptions.DeleteOnClose);

            return File(fs, contentType: "application/zip", fileDownloadName: "output.zip");
        }
    }
}
