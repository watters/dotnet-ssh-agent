using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Watters.SSHAgent.Client
{
    /*
     * https://tools.ietf.org/html/draft-miller-ssh-agent-00
     * https://tools.ietf.org/html/rfc4251
     * https://tools.ietf.org/html/rfc4252
     * https://tools.ietf.org/html/rfc4253
     */

    public class SSHAgentClient : IDisposable
    {
        public SSHAgentClient()
        {
            _socket = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
        }

        public void Connect(EndPoint endpoint)
        {
            _socket.Connect(endpoint);
        }
        
        /*
         * https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-4.4
         *
         * 4.4.  Requesting a list of keys
         *
         *     A client may request a list of keys from an agent using the following
         *     message:
         *
         *        byte                    SSH_AGENTC_REQUEST_IDENTITIES
         *
         *     The agent shall reply with a message with the following preamble.
         *
         *        byte                    SSH_AGENT_IDENTITIES_ANSWER
         *        uint32                  nkeys
         *
         *     Where "nkeys" indicates the number of keys to follow.  Following the
         *     preamble are zero or more keys, each encoded as:
         *
         *        string                  key blob
         *        string                  comment
         *
         *     Where "key blob" is the wire encoding of the public key and "comment"
         *     is a human-readable comment encoded as a UTF-8 string.
         *
         */

        public ReadOnlyCollection<Identity> List()
        {
            SendRequestAndValidateResponse(
                messageNumber: SSH_AGENTC_REQUEST_IDENTITIES,
                expectedResponse: SSH_AGENT_IDENTITIES_ANSWER
            );

            var countOfIdentitiesBytes = new byte[4];
            _socket.Receive(countOfIdentitiesBytes);
            var countOfIdentities = ToNetworkByteOrderUInt32(countOfIdentitiesBytes,0);

            var identities = new List<Identity>();
            for (var i = 0; i < countOfIdentities; i++)
            {
                var blobLengthBytes = new byte[4];
                _socket.Receive(blobLengthBytes);
                var blobLength = ToNetworkByteOrderUInt32(blobLengthBytes, 0);

                var blobBytes = new byte[blobLength];
                _socket.Receive(blobBytes);

                var commentLengthBytes = new byte[4];
                _socket.Receive(commentLengthBytes);
                var commentLength = ToNetworkByteOrderUInt32(commentLengthBytes, 0);

                var commentBytes = new byte[commentLength];
                _socket.Receive(commentBytes);

                identities.Add(new Identity
                {
                    KeyBlob = blobBytes,
                    Comment = commentBytes
                });
            }

            return identities.AsReadOnly();
        }

        public void Dispose()
        {
            _socket.Dispose();
        }

        private void SendRequestAndValidateResponse(byte messageNumber, byte expectedResponse)
        {
            byte[] message = {0, 0, 0, 1, messageNumber};

            _socket.Send(message);

            byte[] responseSizeBuffer = new byte[4];
            _socket.Receive(responseSizeBuffer);
            uint responseSize = ToNetworkByteOrderUInt32(responseSizeBuffer, 0);

            if (responseSize == 0)
                throw new InvalidOperationException("Response is empty.");

            byte[] responseCode = new byte[1];
            _socket.Receive(responseCode);

            if (responseCode.Length == 0)
                throw new InvalidOperationException("Response is empty.");

            if (responseCode[0] == SSH_AGENT_FAILURE)
                throw new InvalidOperationException($"Response code ({responseCode}) indicates failure.");

            if (responseCode[0] != expectedResponse)
                throw new InvalidOperationException($"Agent responded with unexpected" +
                                                    $" response code ({responseCode}) rather than the expected" +
                                                    $" ({expectedResponse})");
        }

        private uint ToNetworkByteOrderUInt32(byte[] bytes, int startIndex)
        {
            byte[] myBytes = new byte[bytes.Length];
            Buffer.BlockCopy(bytes,startIndex,myBytes,0,bytes.Length - startIndex);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(myBytes);

            return BitConverter.ToUInt32(myBytes, startIndex);
        }

        private Socket _socket;

        private const byte SSH_AGENT_FAILURE = 5;
        private const byte SSH_AGENT_SUCCESS = 6;
        private const byte SSH_AGENTC_REQUEST_IDENTITIES = 11;
        private const byte SSH_AGENT_IDENTITIES_ANSWER = 12;
        private const byte SSH_AGENTC_SIGN_REQUEST = 13;
        private const byte SSH_AGENT_SIGN_RESPONSE = 14;

        public class Identity
        {
            public byte[] KeyBlob { get; set; }
            public byte[] Comment { get; set; }
            public string CommentUTF8 => Encoding.UTF8.GetString(Comment);
            public string BlobMD5
            {
                get
                {
                    using (var md5 = System.Security.Cryptography.MD5.Create())
                    {
                        return GetColonDelimitedHex(md5.ComputeHash(KeyBlob));
                    }
                }
            }

            public string BlobSHA256
            {
                get
                {
                    using (var sha256 = System.Security.Cryptography.SHA256.Create())
                    {
                        return GetColonDelimitedHex(sha256.ComputeHash(KeyBlob));
                    }
                }
            }

            private string GetColonDelimitedHex(byte[] bytes)
            {
                return string.Join(":",bytes.Select(b => b.ToString("x2")));
            }
        }
    }    
}