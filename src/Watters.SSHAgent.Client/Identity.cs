using System;
using System.Linq;
using System.Text;

namespace Watters.SSHAgent.Client
{
    public class Identity
    {
        public Identity(byte[] comment, byte[] keyBlob)
        {
            Comment = comment;
            KeyBlob = keyBlob;
        }
        
        public byte[] KeyBlob { get; }
        public byte[] Comment { get; }
        public string CommentUTF8 => Encoding.UTF8.GetString(Comment);
        public string BlobMD5
        {
            get
            {
                using (var md5 = System.Security.Cryptography.MD5.Create())
                {
                    return string.Join(":",md5.ComputeHash(KeyBlob).Select(b => b.ToString("x2")));
                }
            }
        }

        public string BlobSHA256
        {
            get
            {
                using (var sha256 = System.Security.Cryptography.SHA256.Create())
                {
                    return Convert.ToBase64String(sha256.ComputeHash(KeyBlob)).Replace("=","");
                }
            }
        }
    }
}