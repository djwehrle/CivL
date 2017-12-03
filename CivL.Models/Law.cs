using System;
using System.ComponentModel.DataAnnotations;

namespace CivL.Models
{
    public class Law
    {
        [Key]
        public int ID { get; set; }

        [Required]
        [MaxLength(50)]
        public string Name { get; set; }

        [Required]
        public string Text { get; set; }

        public string UserID { get; set; }

        public DateTime UpdateDate { get; set; }
    }
}