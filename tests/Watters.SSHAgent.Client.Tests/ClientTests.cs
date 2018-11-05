using System;
using System.Linq;
using System.Net.Sockets;
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
    }
}