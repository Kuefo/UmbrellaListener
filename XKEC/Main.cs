using Globals;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
 
namespace API {
    class Terminal {
        static void Main(string[] args) { Initialize(); }
        private static void Initialize() {
            API Server = new API();
            Server.Start();
            Console.Title = "XKEC API";
            Console.SetWindowSize(120, 40);
        }
        public static void Write(ConsoleColor Color, string Text) {
            Console.ForegroundColor = Color;
            Console.Write(Text);
            Console.ForegroundColor = ConsoleColor.White;
        }
    }
    
    class API {
        private Thread Thread;
        
        private TcpListener TCPListener = new TcpListener(IPAddress.Any, 5555);
        public void Start() {
            this.Thread = new Thread(new ThreadStart(this.ConnectionLoop));
            this.Thread.Start();
        }
        public static Random Random = new Random();
        public static int GetRandomNumber(int Min, int Max) { return Random.Next(Min, Max); }
        public byte[] ComputeECCDigest(byte[] HVSalt, string CPUKey) {
            for (int i = 0; i < 0x100; i++) {
                if (!Enumerable.SequenceEqual(HVSalt, File.ReadAllBytes("Resources/Salts.bin").Skip(i * 0x10).Take(0x10).ToArray())) continue;
                return File.ReadAllBytes("Resources/Keysets/" + File.ReadAllText("Resources/KeysetIDs/" + CPUKey + ".txt") + "/ECCDigests.bin").Skip(i * 0x14).Take(0x14).ToArray();
            }
            return null;
        }
        public byte[] ComputeHVDigest(byte[] HVSalt, string CPUKey) {
            for (int i = 0; i < 0x100; i++) {
                if (!Enumerable.SequenceEqual(HVSalt, File.ReadAllBytes("Resources/Salts.bin").Skip(i * 0x10).Take(0x10).ToArray())) continue;
                return File.ReadAllBytes("Resources/HVDigests.bin").Skip(i * 0x6).Take(0x6).ToArray();
            }
            return null;
        }
        public byte[] ComputeUpdateSequence(byte[] Index)
        {
            byte[] UpdateSequence = new byte[0x3];
            Buffer.BlockCopy(SHA1ComputeHash(Index), 0, UpdateSequence, 0, 0x3);
            return UpdateSequence;
        }
        public uint ComputeHVStatusFlags(bool CRL, bool FCRT) {
            uint HVStatusFlags = 0x023289D3;
            if (CRL) { HVStatusFlags |= 0x10000; }
            if (FCRT) { HVStatusFlags |= 0x1000000; }
            return HVStatusFlags;
        }
        public uint ComputeConsoleTypeFlags(byte ConsoleIdentifier) {
            uint ConsoleTypeFlags = 0;
            if (ConsoleIdentifier < 0x10) ConsoleTypeFlags = 0x010B0524;
            else if (ConsoleIdentifier < 0x14) ConsoleTypeFlags = 0x010C0AD0;
            else if (ConsoleIdentifier < 0x18) ConsoleTypeFlags = 0x010C0AD8;
            else if (ConsoleIdentifier < 0x52) ConsoleTypeFlags = 0x010C0FFB;
            else if (ConsoleIdentifier < 0x58) ConsoleTypeFlags = 0x0304000D;
            else ConsoleTypeFlags = 0x0304000E;
            return ConsoleTypeFlags;
        }
        public static byte[] SHA1ComputeHash(byte[] Data) {
            SHA1Managed SHA1 = new SHA1Managed();
            return SHA1.ComputeHash(Data);
        }
        private void XKEC(TcpClient TCPClient, byte[] ReceivedBuffer, NetworkStream Stream) {
            IPEndPoint IP = TCPClient.Client.RemoteEndPoint as IPEndPoint;
            byte[] XKECBuffer = File.ReadAllBytes("Resources/Template.bin");
            byte[] CPUKey = new byte[0x10];
            byte[] HVSalt = new byte[0x10];
            bool CRL = false;
            bool FCRT = false;
            bool KVType = false;
            byte ConsoleIdentifier = 0;

            Buffer.BlockCopy(ReceivedBuffer, 0x0, CPUKey, 0x0, 0x10);
            Buffer.BlockCopy(ReceivedBuffer, 0x10, HVSalt, 0x0, 0x10);
            CRL = Convert.ToBoolean(ReceivedBuffer[0x20]);
            FCRT = Convert.ToBoolean(ReceivedBuffer[0x21]);
            KVType = Convert.ToBoolean(ReceivedBuffer[0x22]);
            ConsoleIdentifier = ReceivedBuffer[0x23];
            if (!File.Exists("Resources/KeysetIDs/" + Tools.BytesToHexString(CPUKey) + ".txt") || !CRL) {
                File.WriteAllText("Resources/KeysetIDs/" + Tools.BytesToHexString(CPUKey) + ".txt", "" + GetRandomNumber(1, 11));
            }
            Terminal.Write(ConsoleColor.Green, "[" + DateTime.Now + "]" + "\n");
            Terminal.Write(ConsoleColor.DarkGreen, "IP - ");
            Terminal.Write(ConsoleColor.DarkGray, IP.Address.ToString() + "\n");
            Terminal.Write(ConsoleColor.DarkGreen, "CPUKey - ");
            Terminal.Write(ConsoleColor.DarkGray, Tools.BytesToHexString(CPUKey) + "\n");
            Terminal.Write(ConsoleColor.DarkGreen, "CRL - ");
            Terminal.Write(ConsoleColor.DarkGray, (CRL ? "[T]" : "[F]") + "\n");
            Terminal.Write(ConsoleColor.DarkGreen, "FCRT - ");
            Terminal.Write(ConsoleColor.DarkGray, (FCRT ? "[F]" : "[T]") + "\n");
            Terminal.Write(ConsoleColor.DarkGreen, "KV Type - ");
            Terminal.Write(ConsoleColor.DarkGray, (KVType ? "[1]" : "[2]") + "\n");
            Terminal.Write(ConsoleColor.DarkGreen, "HV Salt - ");
            Terminal.Write(ConsoleColor.DarkGray, Tools.BytesToHexString(HVSalt) + "\n");
            Terminal.Write(ConsoleColor.DarkGreen, "Keyset - ");
            Terminal.Write(ConsoleColor.DarkGray, File.ReadAllText("Resources/KeysetIDs/" + Tools.BytesToHexString(CPUKey) + ".txt") + "\n\n");

            Buffer.BlockCopy((KVType ? BitConverter.GetBytes((ushort)0xD81E).Reverse().ToArray() : BitConverter.GetBytes((ushort)0xD83E).Reverse().ToArray()), 0, XKECBuffer, 0x2E, 0x2);

            Buffer.BlockCopy(ComputeUpdateSequence(CPUKey.Skip(0xB).Take(0x5).Reverse().ToArray()), 0, XKECBuffer, 0x34, 0x3);

            Buffer.BlockCopy(BitConverter.GetBytes(ComputeHVStatusFlags(CRL, FCRT)).Reverse().ToArray(), 0, XKECBuffer, 0x38, 0x4);

            Buffer.BlockCopy(BitConverter.GetBytes(ComputeConsoleTypeFlags(ConsoleIdentifier)).Reverse().ToArray(), 0, XKECBuffer, 0x3C, 0x4);

            Buffer.BlockCopy(ComputeECCDigest(HVSalt, Tools.BytesToHexString(CPUKey)), 0, XKECBuffer, 0x50, 0x14);

            Buffer.BlockCopy(SHA1ComputeHash(CPUKey), 0, XKECBuffer, 0x64, 0x14);

            Buffer.BlockCopy(File.ReadAllBytes("Resources/Keysets/" + File.ReadAllText("Resources/KeysetIDs/" + Tools.BytesToHexString(CPUKey) + ".txt") + "/RSA.bin"), 0, XKECBuffer, 0x78, 0x80);

            Buffer.BlockCopy(ComputeHVDigest(HVSalt, Tools.BytesToHexString(CPUKey)), 0, XKECBuffer, 0xFA, 0x6);
            Stream.Write(XKECBuffer, 0, 0x100);
        }
        private void ReceiveTransmission(object TCPObj) {
            TcpClient TCPClient = (TcpClient)TCPObj;
            NetworkStream NetStream = TCPClient.GetStream();
            IPEndPoint IP = TCPClient.Client.RemoteEndPoint as IPEndPoint;
            byte[] ReceivedBuffer = new byte[0x24];
            if (!File.ReadAllText("Whitelist.txt").Contains(IP.Address.ToString())) {
                Console.Write("[" + DateTime.Now + "]" + " Unaothorized Client " + IP.Address.ToString() + "\n");
                TCPClient.Close();
                return;
            }
            else if (NetStream.Read(ReceivedBuffer, 0, ReceivedBuffer.Length) == ReceivedBuffer.Length) {
                XKEC(TCPClient, ReceivedBuffer, NetStream);
                TCPClient.Close();
            }
            TCPClient.Close();
        }
        private void ConnectionLoop() {
            TCPListener.Start(1);
            TCPListener.Server.ReceiveTimeout = 0;
            for (;; Thread.Sleep(100)) {
                if (TCPListener.Pending()) new Thread(new ParameterizedThreadStart(ReceiveTransmission)).Start(TCPListener.AcceptTcpClient());
            }
        }
    }
}