using System.IO.Compression;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SnowrunnerMergerApi.Data;
using SnowrunnerMergerApi.Exceptions;
using SnowrunnerMergerApi.Models.Saves;
using SnowrunnerMergerApi.Models.Saves.Dtos;
using SnowrunnerMergerApi.Services.Interfaces;

namespace SnowrunnerMergerApi.Services;

public class SavesService : ISavesService
{
    private static readonly string StorageDir = Path.Join("storage", "saves");
    private static readonly string TmpStorageDir = Path.Join(StorageDir, "tmp");
    public static readonly int MaxSaveSize = 50 * 1024 * 1024;

    private readonly ILogger<SavesService> _logger;
    private readonly AppDbContext _dbContext;
    private readonly IUserService _userService;
    
    public SavesService(
        ILogger<SavesService> logger,
        AppDbContext dbContext,
        IUserService userService
    )
    {
        _logger = logger;
        _dbContext = dbContext;
        _userService = userService;
        
        if (!Directory.Exists(StorageDir)) Directory.CreateDirectory(StorageDir);
    }
    
    /// <summary>
    /// Stores a save file for a specified group.
    /// </summary>
    /// <param name="groupId">The ID of the group to store the save file for.</param>
    /// <param name="data">An <see cref="UploadSaveDto"/> object containing the save file and its metadata.</param>
    /// <param name="saveSlot">The slot number to store the save file in.</param>
    /// <returns>A <see cref="StoredSaveInfo"/> object containing information about the stored save file.</returns>
    /// <exception cref="HttpResponseException">
    /// Thrown with different HTTP status codes depending on the validation failure:
    /// <list type="bullet">
    ///     <item>
    ///         HttpStatusCode.BadRequest (400): If the file type is invalid or the save file is too big.
    ///     </item>
    ///     <item>
    ///         HttpStatusCode.NotFound (404): If the group is not found.
    ///     </item>
    ///     <item>
    ///         HttpStatusCode.Unauthorized (401): If the user is not authorized to store the save file.
    ///     </item>
    /// </list>
    /// </exception>
    public async Task<StoredSaveInfo> StoreSave(Guid groupId, UploadSaveDto data, int saveSlot)
    {
        if (data.Save.ContentType != "application/zip") throw new HttpResponseException(HttpStatusCode.BadRequest, "Invalid file type");
        
        var sessionData = _userService.GetUserSessionData();
        
        var group = _dbContext.SaveGroups
            .Include(g => g.StoredSaves)
            .FirstOrDefault(g => g.Id == groupId);
        
        if (group is null) throw new HttpResponseException(HttpStatusCode.NotFound, "Group not found");

        if (!group.OwnerId.Equals(sessionData.Id)) throw new HttpResponseException(HttpStatusCode.Unauthorized);
        
        StoredSaveInfo? oldestSave = null; 
        if (group.StoredSaves.Count >= 3)
        {
            if ( saveSlot < 0 || saveSlot >= group.StoredSaves.Count)
            {
                oldestSave = group.StoredSaves.OrderBy(s => s.UploadedAt).First();
            }
            else
            {
                oldestSave = group.StoredSaves.OrderByDescending(s => s.UploadedAt).ElementAt(saveSlot);
            }
        }

        var saveInfo = new StoredSaveInfo
        {
            Description = data.Description,
            SaveNumber = data.SaveNumber,
            UploadedAt = DateTime.UtcNow,
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

        if (oldestSave is not null)
        {
            await RemoveSave(oldestSave);
        }

        return saveInfo;
    }
    
    /// <summary>
    ///     Merges two save files from a group and returns the path to the merged save file.
    /// </summary>
    /// <param name="groupId">The ID of the group to merge the save files for.</param>
    /// <param name="data">A <see cref="MergeSavesDto"/> object containing the save file to merge and its metadata.</param>
    /// <param name="storedSaveNumber">The slot number of the stored save file to merge with.</param>
    /// <returns>The path to the merged save file.</returns>
    /// <exception cref="HttpResponseException">
    ///     Thrown with different HTTP status codes depending on the validation failure:
    ///     <list type="bullet">
    ///         <item>
    ///             HttpStatusCode.BadRequest (400): If the file type is invalid, the save file is too big, the save number is invalid, or the save is invalid.
    ///         </item>
    ///         <item>
    ///             HttpStatusCode.NotFound (404): If the group is not found.
    ///         </item>
    ///         <item>
    ///             HttpStatusCode.Unauthorized (401): If the user is not authorized to merge the save files.
    ///         </item>
    ///     </list>
    /// </exception>
    public async Task<string> MergeSaves(Guid groupId, MergeSavesDto data, int storedSaveNumber)
    {
        if (data.Save.ContentType != "application/zip") throw new HttpResponseException(HttpStatusCode.BadRequest, "Invalid file type");
        
        var sessionData = _userService.GetUserSessionData();
        
        var group = _dbContext.SaveGroups
            .Include(g => g.Members)
            .FirstOrDefault(g => g.Id == groupId);
        
        if (group is null) throw new HttpResponseException(HttpStatusCode.NotFound, "Group not found");
        
        if (group.Members.All(m => !m.Id.Equals(sessionData.Id))) throw new HttpResponseException(HttpStatusCode.Unauthorized);
        
        var saves = _dbContext.StoredSaves
            .Where(s => s.SaveGroupId == groupId)
            .OrderByDescending(s => s.UploadedAt)
            .ToList();
        
        if (saves.Count == 0) throw new HttpResponseException(HttpStatusCode.BadRequest, "No group saves found");
        
        if (saves.Count < storedSaveNumber) storedSaveNumber = saves.Count - 1;
        
        if (storedSaveNumber < 0) throw new HttpResponseException(HttpStatusCode.BadRequest, "Invalid save number");
        
        if (!Directory.Exists(TmpStorageDir)) Directory.CreateDirectory(TmpStorageDir);
        
        var tmpStorage = Path.Join(TmpStorageDir, sessionData.Id.ToString());
        var tmpSaveStorage = Path.Join(tmpStorage, "save");
        var outputDirectory = Path.Join(tmpStorage, "output");
        
        if (Directory.Exists(tmpStorage)) Directory.Delete(tmpStorage, true);

        Directory.CreateDirectory(tmpStorage);
        Directory.CreateDirectory(tmpSaveStorage);
        Directory.CreateDirectory(outputDirectory);

        var zippedSavePath = Path.Join(tmpSaveStorage, "tmp.zip");
        await using var stream = new FileStream(zippedSavePath, FileMode.Create);

        await data.Save.CopyToAsync(stream);
        
        stream.Close();

        var zippedSave = ZipFile.OpenRead(zippedSavePath);

        var declaredSize = zippedSave.Entries.Sum(e => e.Length);
        if (declaredSize > MaxSaveSize)
        {
            Directory.Delete(tmpSaveStorage, true);
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Save is too big");
        }
        
        zippedSave.Dispose();
        
        ZipFile.ExtractToDirectory(zippedSavePath, tmpSaveStorage, overwriteFiles: true);
        
        File.Delete(zippedSavePath);
        
        if (!ValidateSaveFiles(tmpSaveStorage, data.SaveNumber))
        {
            Directory.Delete(tmpSaveStorage, true);
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Save is invalid");
        }

        var storedSaveData = saves[storedSaveNumber];
        
        var storedSaveDirectory = Path.Join(StorageDir, storedSaveData.Id.ToString());
        
        var mapDataFilesRegex = new Regex($@"\b({(storedSaveData.SaveNumber > 0 ? storedSaveData.SaveNumber.ToString() + '_' : "")}(fog|sts)_.*\.dat)\b", RegexOptions.Multiline);

        var mapDataFiles = Directory
            .GetFiles(storedSaveDirectory)
            .Where(f => mapDataFilesRegex.IsMatch(Path.GetFileName(f)));
        
        // Copy map data files to output from stored save
        foreach (var file in mapDataFiles)
        {
            var currentFileName = Path.GetFileName(file);
            if (storedSaveData.SaveNumber > 0)
            {
                currentFileName = currentFileName[2..];
            }
            
            var filePrefix = data.OutputSaveNumber > 0 ? data.OutputSaveNumber.ToString() + '_' : "";
            var outputFileName = data.SaveNumber == 0
                ? filePrefix + currentFileName
                : filePrefix + currentFileName[2..];
            var outputFilePath = Path.Join(outputDirectory, outputFileName);
            
            File.Copy(file, outputFilePath, overwrite: true);
        }

        var uploadedSave = LoadSave(tmpSaveStorage, data.SaveNumber);
        var uploadedSaveFilePath = Path.Join(tmpSaveStorage, $"CompleteSave{(data.SaveNumber > 0 ? data.SaveNumber.ToString() : "")}.dat");
        if (File.Exists(uploadedSaveFilePath))
        {
            File.Delete(uploadedSaveFilePath);
        }
        
        var storedSave = LoadSave(storedSaveDirectory, storedSaveData.SaveNumber);
        
        if (uploadedSave is null || storedSave is null)
        {
            Directory.Delete(tmpStorage, true);
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Save is invalid");
        }
        
        var outputSaveData = MergeSaveData(uploadedSave, storedSave, data.OutputSaveNumber);
        
        if (outputSaveData is null)
        {
            Directory.Delete(tmpStorage, true);
            throw new HttpResponseException(HttpStatusCode.BadRequest, "Save is invalid");
        }

        var outputSave = new Dictionary<string, dynamic>()
        {
            { $"CompleteSave{(data.OutputSaveNumber > 0 ? data.OutputSaveNumber.ToString() : "")}", outputSaveData },
            { "cfg_version", uploadedSave.RawSaveData["cfg_version"] }
        };
        
        var outputSaveJson = JsonSerializer.Serialize(outputSave);
        var outputSavePath = Path.Join(outputDirectory,
            $"CompleteSave{(data.OutputSaveNumber > 0 ? data.OutputSaveNumber.ToString() : "")}.dat");
        
        await File.WriteAllTextAsync(outputSavePath, outputSaveJson);
        
        var outputZipPath = Path.Join(tmpStorage, "output.zip");
        
        if (File.Exists(outputZipPath)) File.Delete(outputZipPath);
        
        ZipFile.CreateFromDirectory(outputDirectory, outputZipPath);
        
        Directory.Delete(tmpSaveStorage, true);
        Directory.Delete(outputDirectory, true);

        return outputZipPath;
    }

    /// <summary>
    ///     Removes a save file from a group.
    /// </summary>
    /// <param name="saveId">The ID of the save file to remove.</param>
    /// <exception cref="HttpResponseException">
    ///     Thrown with different HTTP status codes depending on the validation failure:
    ///     <list type="bullet">
    ///         <item>
    ///             HttpStatusCode.NotFound (404): If the save file is not found.
    ///         </item>
    ///         <item>
    ///             HttpStatusCode.Unauthorized (401): If the user is not authorized to remove the save file.
    ///         </item>
    ///     </list>
    /// </exception>
    public Task RemoveSave(Guid saveId)
    {
        var sessionData = _userService.GetUserSessionData();
        
        var save = _dbContext.StoredSaves
            .Include(s => s.SaveGroup)
            .FirstOrDefault(s => s.Id == saveId);
        
        if (save is null) throw new HttpResponseException(HttpStatusCode.NotFound, "Save not found");
        
        if (!save.SaveGroup.OwnerId.Equals(sessionData.Id)) throw new HttpResponseException(HttpStatusCode.Unauthorized);

        return RemoveSave(save);
    }

    /// <summary>
    ///     Removes stored save data from the database and the file system.
    /// </summary>
    /// <param name="save">The <see cref="StoredSaveInfo"/> object to remove.</param>
    public Task RemoveSave(StoredSaveInfo save)
    {
        var saveDirectory = Path.Join(StorageDir, save.Id.ToString());
        
        if (Directory.Exists(saveDirectory))
        {
            Directory.Delete(saveDirectory, true);
        }
        
        _dbContext.StoredSaves.Remove(save);
        
        return _dbContext.SaveChangesAsync();
    }
    
    /// <summary>
    ///     Merges two save files
    /// </summary>
    /// <param name="uploadedSave">A <see cref="Save"/> to merge with stored save.</param>
    /// <param name="storedSave">A <see cref="Save"/> to merge with uploaded save.</param>
    /// <param name="outputSaveNumber">The save slot number of the output save.</param>
    /// <returns>A <see cref="SaveData"/> object containing the merged save data.</returns>
    private SaveData? MergeSaveData(Save uploadedSave, Save storedSave, int outputSaveNumber)
    {
        if (uploadedSave.SaveData is null || storedSave.SaveData is null) return null;
        
        var uploadedProfileData = uploadedSave.SaveData.SslValue.persistentProfileData;
        var storedProfileData = storedSave.SaveData.SslValue.persistentProfileData;

        uploadedProfileData.newTrucks = uploadedProfileData.newTrucks.Union(storedProfileData.newTrucks).ToList();

        uploadedProfileData.discoveredUpgrades = Helpers.MergeDictionaries(
            uploadedProfileData.discoveredUpgrades,
            storedProfileData.discoveredUpgrades
        );

        uploadedProfileData.discoveredUpgrades = Helpers.MergeDictionaries(
            uploadedProfileData.discoveredUpgrades,
            storedProfileData.discoveredUpgrades
        );

        uploadedProfileData.contestTimes = Helpers.MergeDictionaries(
            uploadedProfileData.contestTimes,
            storedProfileData.contestTimes
        );

        var outputSaveData = storedSave.SaveData;
        outputSaveData.SslValue.persistentProfileData = uploadedProfileData;
        outputSaveData.SslValue.gameStat = uploadedSave.SaveData.SslValue.gameStat;
        // outputSaveData.SslValue.garagesData = uploadedSave.SaveData.SslValue.garagesData;
        outputSaveData.SslValue.waypoints = uploadedSave.SaveData.SslValue.waypoints;
        outputSaveData.SslValue.saveId = outputSaveNumber;
        
        return outputSaveData;
    }
    
    /// <summary>
    ///     Validates the save files in a directory.
    /// </summary>
    /// <param name="path">The path to the directory containing the save files.</param>
    /// <param name="saveNumber">The save number to validate.</param>
    /// <returns>True if the save files are valid, false otherwise.</returns>
    private bool ValidateSaveFiles(string path, int saveNumber)
    {
        var saveFileName = $"CompleteSave{(saveNumber > 0 ? saveNumber : "")}.dat";
        var files = Directory
            .GetFiles(path)
            .Select(Path.GetFileName)
            .ToList();

        if (!files.Contains(saveFileName)) return false;
        
        var mapDataRegex = new Regex($@"\b({(saveNumber > 0 ? saveNumber.ToString() + '_' : "")}(fog|sts)_.*\.dat)\b", RegexOptions.Multiline);
        
        // Count the number of files matching the regex
        var count = files.Count(file => mapDataRegex.IsMatch(Path.GetFileName(file)));

        return count >= 2;
    }
    
    /// <summary>
    ///     Loads a save from a directory.
    /// </summary>
    /// <param name="saveFileDirectory">The directory containing the save file.</param>
    /// <param name="saveFileNumber">The save file number.</param>
    /// <returns>A <see cref="Save"/> object containing the save data.</returns>
    private Save? LoadSave(string saveFileDirectory, int saveFileNumber)
    {
        var saveFilePath = Path.Join(saveFileDirectory, $"CompleteSave{(saveFileNumber > 0 ? saveFileNumber.ToString() : "")}.dat");

        if (!File.Exists(saveFilePath)) return null;

        var saveFileJson = File.ReadAllText(saveFilePath);
        if (saveFileJson[^1] != '}')
        {
            saveFileJson = saveFileJson.Remove(saveFileJson.Length - 1, 1);
        }

        var saveFileData = JsonSerializer.Deserialize<Dictionary<string, dynamic>>(saveFileJson);
        
        return saveFileData is null ? null : new Save(saveFileData, saveFileNumber);
    }
}