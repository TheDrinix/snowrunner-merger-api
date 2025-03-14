namespace SnowrunnerMergerApi.Models.Auth.Google;

public enum GoogleResTokenType
{
    AccessToken = 1 << 0,
    LinkingToken = 1 << 1,
    CompletionToken = 1 << 2
}