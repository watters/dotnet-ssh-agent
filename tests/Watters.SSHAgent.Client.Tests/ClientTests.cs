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
    public class ClientTests : IDisposable
    {
        public ClientTests()
        {
            _client = new SSHAgentClient(
                new UnixDomainSocketEndPoint(Environment.GetEnvironmentVariable("SSH_AUTH_SOCK")));
        }

        [Fact]
        public void CheckListIdentities()
        {
            Assert.True(_client.List().Any());
        }

        [Fact]
        public void CheckSHA256Fingerprint()
        {
            Assert.NotNull(
                _client.List().SingleOrDefault(
                    i => $"SHA256:{i.BlobSHA256}" == Environment.GetEnvironmentVariable("SHA256_FINGERPRINT")
                ));
        }

        [Fact]
        public void CheckMD5Fingerprint()
        {
            Assert.NotNull(
                _client.List().SingleOrDefault(
                    i => $"MD5:{i.BlobMD5}" == Environment.GetEnvironmentVariable("MD5_FINGERPRINT")
                ));
        }

        [Fact]
        public void CheckSignWithRSAKey()
        {
            var identities = _client.List();

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

            byte[] agentSignature = _client.Sign(rsaAgentKey, input).Signature;

            Assert.Equal(agentSignature, privateKeySignature);
        }

        [Fact]
        public void CheckSignWithECDSAKey()
        {
        }

        public void Dispose()
        {
            _client.Dispose();
        }

        private readonly SSHAgentClient _client;
    }
}