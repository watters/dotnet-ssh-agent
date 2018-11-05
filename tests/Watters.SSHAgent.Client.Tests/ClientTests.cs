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

                string mantaKeyId = Environment.GetEnvironmentVariable("MANTA_KEY_ID");
                var mantaKey = identities.Single(i => i.BlobMD5 == mantaKeyId);
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

                var rsaAgentKey = client.List().SingleOrDefault(i => i.CommentUTF8 == rsaKeyFilePath);

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