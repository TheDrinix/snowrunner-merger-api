namespace SnowrunnerMergerApi;

public class Helpers
{
    public static Dictionary<T1, T2> MergeDictionaries<T1, T2>(Dictionary<T1, T2> dict1, Dictionary<T1, T2> dict2) where T1 : notnull
    {
        var merged = dict1
            .Concat(dict2)
            .ToLookup(k => k.Key, v => v.Value)
            .ToDictionary(k => k.Key, v => v.Last());

        return merged;
    }

    public static DateTime HexUnixTimestampToDateTime(string timestamp)
    {
        // Snowrunner save timestamps have addition 3 zeros on end of the timestamp for some reason
        var unixTimeStamp = Convert.ToInt64(timestamp, 16) / 1000;
        
        var dateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)
            .AddSeconds(unixTimeStamp)
            .ToLocalTime();

        return dateTime;
    }
}