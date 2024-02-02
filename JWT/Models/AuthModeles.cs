namespace JWT.Models
{
    public class AuthModeles
    {
        public string Message { get; set; }
        public bool IsAuthinticated { get; set; }
        public string UserName {  get; set; }
        public string Email {  get; set; }
        public List<string> Roles { get; set; }
        public string Token { get; set; }
        public DateTime Expireson {  get; set; }
    }
}
