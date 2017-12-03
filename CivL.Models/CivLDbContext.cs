using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.Linq;
using System.Threading.Tasks;

namespace CivL.Models
{
    public class CivLDbContext : DbContext
    {
        public CivLDbContext(string userID)
            : base("CivL")
        {
            this.userID = userID;

            Configuration.LazyLoadingEnabled = false;
        }

        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
        }

        public sealed override int SaveChanges()
        {
            AddAuditInfo();

            return base.SaveChanges();
        }

        public sealed override Task<int> SaveChangesAsync()
        {
            AddAuditInfo();

            return base.SaveChangesAsync();
        }

        private void AddAuditInfo()
        {
            DateTime now = DateTime.Now;

            List<DbEntityEntry> entities = ChangeTracker.Entries().Where(e => e.State == EntityState.Added || e.State == EntityState.Modified).ToList();

            foreach (DbEntityEntry entity in entities)
            {
                entity.Property("UserID").CurrentValue = userID;
                entity.Property("UpdateDate").CurrentValue = now;
            }
        }
        
        public DbSet<Law> Laws { get; set; }

        private string userID;
    }
}