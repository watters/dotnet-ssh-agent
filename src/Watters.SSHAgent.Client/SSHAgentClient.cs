using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
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

    public partial class SSHAgentClient : IDisposable
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
                request: new byte[] {SSH_AGENTC_REQUEST_IDENTITIES},
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
                (
                    keyBlob: blobBytes,
                    comment: commentBytes
                ));
            }

            return identities.AsReadOnly();
        }

         /*
         * https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-4.5
         * 
         * 4.5.  Private key operations
         *
         *    A client may request the agent perform a private key signature
         *    operation using the following message:
         *
         *        byte                    SSH_AGENTC_SIGN_REQUEST
         *        string                  key blob
         *        string                  data
         *        uint32                  flags
         *
         *    Where "key blob" is the key requested to perform the signature,
         *    "data" is the data to be signed and "flags" is a bitfield containing
         *    the bitwise OR of zero or more signature flags (see below).
         *
         *    If the agent is unable or unwilling to generate the signature (e.g.
         *    because it doesn't have the specified key, or the user refused
         *    confirmation of a constrained key), it must reply with a
         *    SSH_AGENT_FAILURE message.
         *
         *    On success, the agent shall reply with:
         * 
         *        byte                    SSH_AGENT_SIGN_RESPONSE
         *        string                  signature
         *
         *    The signature format is specific to the algorithm of the key type in
         *    use.  SSH protocol signature formats are defined in [RFC4253] for
         *    "ssh-rsa" and "ssh-dss" keys, in [RFC5656] for "ecdsa-sha2-*" keys
         *    and in [I-D.ietf-curdle-ssh-ed25519] for "ssh-ed25519" keys.
         *
         * 4.5.1.  Signature flags
         *
         *    Two flags are currently defined for signature request messages:
         *    SSH_AGENT_RSA_SHA2_256 and SSH_AGENT_RSA_SHA2_512.  These two flags
         *    are only valid for "ssh-rsa" keys and request that the agent return a
         *    signature using the "rsa-sha2-256" or "rsa-sha2-515" signature
         *    methods respectively.  These signature schemes are defined in
         *    [I-D.ietf-curdle-rsa-sha2].
         */
        
        public SignResponse Sign(Identity identity, byte[] data)
        {
            using (var request = new MemoryStream())
            {
                request.WriteByte(SSH_AGENTC_SIGN_REQUEST);
                
                // key blob = uint32 length of key bytes + key bytes
                request.Write(
                    buffer: ToNetworkByteOrderBytes((uint) identity.KeyBlob.Length), 
                    offset: 0, 
                    count: 4
                );
                request.Write(
                    buffer: identity.KeyBlob,
                    offset: 0,
                    count: identity.KeyBlob.Length
                );
                
                // data = uint32 length of data + data
                request.Write(
                    buffer: ToNetworkByteOrderBytes((uint) data.Length),
                    offset: 0,
                    count: 4);
                request.Write(
                    buffer: data,
                    offset: 0,
                    count:data.Length
                );
                
                // write flags -- uint32 of flags
                request.Write(new byte[] {0, 0, 0, 0}, 0, 4);
                
                var remainingResponseSize = SendRequestAndValidateResponse(request.ToArray(),SSH_AGENT_SIGN_RESPONSE);

                byte[] response = new byte[remainingResponseSize];
                _socket.Receive(response);

                using (var responseStream = new MemoryStream(response))
                {
                    var signatureStructLengthBytes = new byte[4];
                    responseStream.Read(signatureStructLengthBytes, 0, signatureStructLengthBytes.Length);

                    var formatLengthBytes = new byte[4];
                    responseStream.Read(formatLengthBytes, 0, formatLengthBytes.Length);
                    uint formatLength = ToNetworkByteOrderUInt32(formatLengthBytes,0);

                    var formatBytes = new byte[formatLength];
                    responseStream.Read(formatBytes, 0, formatBytes.Length);
                    string format = Encoding.UTF8.GetString(formatBytes);

                    var signatureLengthBytes = new byte[4];
                    responseStream.Read(signatureLengthBytes, 0, signatureLengthBytes.Length);
                    uint signatureLength = ToNetworkByteOrderUInt32(signatureLengthBytes, 0);

                    var signatureBytes = new byte[signatureLength];
                    responseStream.Read(signatureBytes, 0, signatureBytes.Length);
                    
                    return new SignResponse
                    (
                        format: format,
                        signature: signatureBytes
                    );
                }
            }
        }
        
        public void Dispose()
        {
            _socket.Dispose();
        }

        private uint SendRequestAndValidateResponse(byte[] request, byte expectedResponse)
        {
            byte[] message = new byte[4 + request.Length];
            byte[] messageNumberLength = ToNetworkByteOrderBytes((uint) request.Length);
            
            Buffer.BlockCopy(messageNumberLength,0,message,0,messageNumberLength.Length);
            Buffer.BlockCopy(request,0,message,messageNumberLength.Length,request.Length);

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

            return responseSize - (uint) responseCode.Length;
        }

        private byte[] ToNetworkByteOrderBytes(uint length)
        {
            byte[] bytes = BitConverter.GetBytes(length);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(bytes);

            return bytes;
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
        private const byte SSH_AGENTC_REQUEST_IDENTITIES = 11;
        private const byte SSH_AGENT_IDENTITIES_ANSWER = 12;
        private const byte SSH_AGENTC_SIGN_REQUEST = 13;
        private const byte SSH_AGENT_SIGN_RESPONSE = 14;
    }    
}