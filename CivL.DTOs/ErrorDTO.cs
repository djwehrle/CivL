namespace CivL.DTOs
{
    public class ErrorDTO
    {
        public string Message
        {
            get
            {
                return !string.IsNullOrWhiteSpace(message) ? message : "An error occurred while processing your request.";
            }

            set
            {
                message = value;
            }
        }

        public string MessageDetail { get; set; }

        private string message { get; set; }
    }
}