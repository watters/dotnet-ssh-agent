namespace Watters.SSHAgent.Client
{
    public class SignatureResponse
    {
        public SignatureResponse(string format, byte[] signature)
        {
            Format = format;
            Signature = signature;
        }
        public string Format { get; }
        public byte[] Signature { get; }
    }
}