using System.IO.Compression;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SnowrunnerMergerApi.Data;
using SnowrunnerMergerApi.Exceptions;
using SnowrunnerMergerApi.Models.Saves;
using SnowrunnerMergerApi.Models.Saves.Dtos;

namespace SnowrunnerMergerApi.Services;

public interface ISavesService
{
    Task<StoredSaveInfo> StoreSave(Guid groupId, UploadSaveDto data);
}

public class SavesService : ISavesService
{
    private static readonly string StorageDir = Path.Join("storage", "saves");
    public static readonly int MaxSaveSize = 50 * 1024 * 1024;

    private readonly ILogger<SavesService> _logger;
    private readonly AppDbContext _dbContext;
    private readonly IAuthService _authService;
    
    public SavesService(
        ILogger<SavesService> logger,
        AppDbContext dbContext,
        IAuthService authService
    )
    {
        _logger = logger;
        _dbContext = dbContext;
        _authService = authService;
        
        if (!Directory.Exists(StorageDir)) Directory.CreateDirectory(StorageDir);
    }
    public async Task<StoredSaveInfo> StoreSave(Guid groupId, UploadSaveDto data)
    {
        var sessionData = _authService.GetUserSessionData();
        
        var group = _dbContext.SaveGroups
            .Include(g => g.StoredSaves)
            .FirstOrDefault(g => g.Id == groupId);
        
        if (group is null) throw new HttpResponseException(HttpStatusCode.NotFound, "Group not found");

        if (!group.OwnerId.Equals(sessionData.Id)) throw new HttpResponseException(HttpStatusCode.Unauthorized);

        var saveInfo = new StoredSaveInfo
        {
            Description = data.Description,
            SaveNumber = data.SaveNumber,
            UploadedAt = DateTime.Now,
            SaveGroupId = group.Id
        };
        
        _dbContext.StoredSaves.Add(saveInfo);

        var saveId = saveInfo.Id.ToString();
        var saveDirectory = Path.Join(StorageDir, saveId);

        if (!Directory.Exists(saveDirectory)) Directory.CreateDirectory(saveDirectory);

        var zipFilePath = Path.Join(saveDirectory, "tmp.zip");

        await using var stream = new FileStream(zipFilePath, FileMode.Create);
        
        await data.Save.CopyToAsync(stream);
        
        stream.Close();

        var zipfile = ZipFile.OpenRead(zipFilePath);
        
        var declaredSize = zipfile.Entries.Sum(e => e.Length);

        if (declaredSize > MaxSaveSize)
        {
            Directory.Delete(saveDirectory, true);
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Save is too big");
        }
        
        ZipFile.ExtractToDirectory(zipFilePath, saveDirectory);
        
        zipfile.Dispose();
        
        File.Delete(zipFilePath);
        
        if (!ValidateSaveFiles(saveDirectory, data.SaveNumber))
        {
            Directory.Delete(saveDirectory, true);
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Save is invalid");
        }

        await _dbContext.SaveChangesAsync();

        return saveInfo;
    }

    private bool ValidateSaveFiles(string path, int saveNumber)
    {
        saveNumber--;

        var saveFileName = $"CompleteSave{(saveNumber > 0 ? saveNumber : "")}.dat";
        var files = Directory.GetFiles(path);

        if (!files.Contains(saveFileName)) return false;
        
        var mapDataRegex = new Regex($@"\b({(saveNumber > 0 ? saveNumber.ToString() + '_' : "")}(fog|sts)_.*\.dat)\b", RegexOptions.Multiline);
        
        // Count the number of files matching the regex
        var count = files.Count(file => mapDataRegex.IsMatch(file));

        return count >= 2;
    }
}