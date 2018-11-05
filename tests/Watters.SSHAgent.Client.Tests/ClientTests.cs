using System;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Xunit;

namespace Watters.SSHAgent.Client.Tests
{
    public class ClientTests
    {
        [Fact]
        public void CheckListIdentities()
        {
            using (var client = new SSHAgentClient())
            {
                client.Connect(new UnixDomainSocketEndPoint(Environment.GetEnvironmentVariable("SSH_AUTH_SOCK")));
                var identities = client.List();

                string md5Fingerprint = Environment.GetEnvironmentVariable("MD5_FINGERPRINT");
                var md5Result = identities.SingleOrDefault(i => $"MD5:{i.BlobMD5}" == md5Fingerprint);

                string sha256Fingerprint = Environment.GetEnvironmentVariable("SHA256_FINGERPRINT");
                var sha256Result = identities.SingleOrDefault(i => $"SHA256:{i.BlobSHA256}" == sha256Fingerprint);

                Assert.NotNull(md5Result);
                Assert.NotNull(sha256Result);
            }
        }

        [Fact]
        public void CheckSignForRSA()
        {
            using (var client = new SSHAgentClient())
            {
                client.Connect(new UnixDomainSocketEndPoint(Environment.GetEnvironmentVariable("SSH_AUTH_SOCK")));

                var identities = client.List();
                
                string homeDir = Environment.GetEnvironmentVariable("HOME");
                string rsaKeyFilePath = $"{homeDir}/.ssh/id_rsa";

                var rsaAgentKey = identities.SingleOrDefault(i => i.CommentUTF8 == rsaKeyFilePath);

                AsymmetricCipherKeyPair key;
                using (StreamReader keyFileReader = File.OpenText(rsaKeyFilePath))
                {
                    key = new PemReader(keyFileReader).ReadObject() as AsymmetricCipherKeyPair;

                    if (key == null)
                        throw new ArgumentException("Key file is not a valid key.", nameof(rsaKeyFilePath));
                }
                
                ISigner signer = SignerUtilities.GetSigner("SHA1WITHRSA");
                signer.Init(true, key.Private);

                var input = Encoding.UTF8.GetBytes("Hello, World!");
                signer.BlockUpdate(input, 0, input.Length);
                byte[] privateKeySignature = signer.GenerateSignature();
                byte[] agentSignature = client.Sign(rsaAgentKey, input).Signature;

                Assert.Equal(agentSignature,privateKeySignature);
            }
        }
    }
}