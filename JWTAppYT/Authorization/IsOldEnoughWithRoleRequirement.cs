using Microsoft.AspNetCore.Authorization;

namespace JWTAppYT.Authorization
{
    public class IsOldEnoughWithRoleRequirement : IAuthorizationRequirement
    {
        public IsOldEnoughWithRoleRequirement(int minAge)
        {
            MinAge = minAge;
        }

        public int MinAge { get; set; }
    }
}
