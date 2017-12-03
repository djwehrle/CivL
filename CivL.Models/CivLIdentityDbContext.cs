using Microsoft.AspNet.Identity.EntityFramework;

namespace CivL.Models
{
    public class CivLIdentityDbContext : IdentityDbContext<ApplicationUser>
    {
        public CivLIdentityDbContext()
            : base("CivL", throwIfV1Schema: false)
        {
        }

        public static CivLIdentityDbContext Create()
        {
            return new CivLIdentityDbContext();
        }
    }
}