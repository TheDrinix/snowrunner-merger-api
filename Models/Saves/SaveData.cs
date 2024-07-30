namespace SnowrunnerMergerApi.Models.Saves;

public class SaveData
{
    public string SslType { get; set; }
    public SslValue SslValue { get; set; }
}

public class SslValue
{
    public string lastLoadedLevel { get; set; }
    public bool objectivesValidated { get; set; }
    public int objVersion { get; set; }
    public int saveId { get; set; }
    public object objectiveStates { get; set; }
    public int birthVersion { get; set; }
    public object upgradesGiverData { get; set; }
    public string worldConfiguration { get; set; }
    public int gameDifficultyMode { get; set; }
    public object modTruckOnLevels { get; set; }
    public object levelGarageStatuses { get; set; }
    public bool isHardMode { get; set; }
    public object forcedModelStates { get; set; }
    public List<string> viewedUnactivatedObjectives { get; set; }
    public int lastLevelState { get; set; }
    public double gameTime { get; set; }
    public object hiddenCargoes { get; set; }
    public int metricSystem { get; set; }
    public object garagesShopData { get; set; }
    public object gameDifficultySettings { get; set; }
    public object savedCargoNeedToBeRemovedOnRestart { get; set; }
    public object gameStat { get; set; }
    public List<string> finishedObjs { get; set; }
    public List<object> givenTrialRewards { get; set; }
    public List<string> discoveredObjectives { get; set; }
    public string trackedObjective { get; set; }
    public object waypoints { get; set; }
    public object garagesData { get; set; }
    public object modTruckRefundValues { get; set; }
    public object watchPointsData { get; set; }
    public List<string> visitedLevels { get; set; }
    public object cargoLoadingCounts { get; set; }
    public object upgradableGarages { get; set; }
    public PersistentProfileData persistentProfileData { get; set; }
    public object modTruckTypesRefundValues { get; set; }
    public SaveTime saveTime { get; set; }
    public object tutorialStates { get; set; }
    public object justDiscoveredObjects { get; set; }
    public List<string> discoveredObjects { get; set; }
    public object gameStatByRegion { get; set; }
    public bool isFirstGarageDiscovered { get; set; }
    public int lastPhantomMode { get; set; }
}

public class PersistentProfileData
{
    public int money { get; set; }
    public object distance { get; set; }
    public List<string> dlcNotes { get; set; }
    public object ownedTrucks { get; set; }
    public int experience { get; set; }
    public List<string> newTrucks { get; set; }
    public object contestAttempts { get; set; }
    public int customizationRefundMoney { get; set; }
    public List<object> trucksInWarehouse { get; set; }
    public int rank { get; set; }
    public object refundTruckDescs { get; set; }
    public object contestLastTimes { get; set; }
    public bool isNewProfile { get; set; }
    public Dictionary<string, object> discoveredTrucks { get; set; }
    public Dictionary<string, object> discoveredUpgrades { get; set; }
    public object damagableAddons { get; set; }
    public Dictionary<string, int> contestTimes { get; set; }
    public List<string> knownRegions { get; set; }
    public object unlockedItemNames { get; set; }
    public List<object> refundGarageTruckDescs { get; set; }
    public object addons { get; set; }
    public int refundMoney { get; set; }
    public object userId { get; set; }
}

public class SaveTime
{
    public string timestamp { get; set; }
}