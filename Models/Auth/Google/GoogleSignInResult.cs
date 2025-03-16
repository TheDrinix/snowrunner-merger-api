using SnowrunnerMergerApi.Models.Auth.Dtos;
using SnowrunnerMergerApi.Models.Auth.Tokens;

namespace SnowrunnerMergerApi.Models.Auth.Google;

public abstract record GoogleSignInResult
{
    public record GoogleSignInSuccess(LoginResponseDto data) : GoogleSignInResult;
    public record GoogleSignInLinkRequired(AccountLinkingToken linkingToken) : GoogleSignInResult;
    public record GoogleSignInAccountSetupRequired(AccountCompletionToken completionToken) : GoogleSignInResult;
};