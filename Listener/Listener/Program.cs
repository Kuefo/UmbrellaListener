using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Listener.Helpers;
using System.Collections.Specialized;
namespace ClientListener
{
    class Program
    {
        private TcpListener tcpListener;
        private static string APIUrl = "http:///XBLUmbrella/auth/";

        public static String code(string Url)
        {
            HttpWebRequest myRequest = (HttpWebRequest)WebRequest.Create(Url);
            myRequest.Method = "GET";
            WebResponse myResponse = myRequest.GetResponse();
            StreamReader sr = new StreamReader(myResponse.GetResponseStream(), System.Text.Encoding.UTF8);
            string result = sr.ReadToEnd();
            sr.Close();
            myResponse.Close();

            return result;
        }
        static void Main(string[] args)
        {
            Program server = new Program();
            server.SetupServer();
        }
        int Chals = 0;
        void SetupServer() {
            Thread.Sleep(1000);
            int PORT = 4000;
            tcpListener = new TcpListener(IPAddress.Any, PORT);
            new Thread(new ThreadStart(() => acceptClient())).Start();
            Tools.AppendText("STARTED" + "\n", ConsoleColor.Green);
            Tools.AppendText("[XBLUmbrella] Success | Port [" + PORT.ToString() + "]\n", ConsoleColor.White);
            Console.Title = "XBLUmbrella";
        }
        void acceptClient() {
            tcpListener.Start();
            while (true)
            {
                Thread.Sleep(100);
                if (tcpListener.Pending())
                    new Thread(new ThreadStart(() => handleClient(tcpListener.AcceptTcpClient()))).Start();
            }
        }
        static byte[] RandomBytes(int length)
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] data = new byte[length];
                rng.GetBytes(data);
                return data;
            }
        }
        public static byte[] GenerateXKEChallenge(byte[] CPUKey, byte[] HVSalt, bool CRL, bool FCRT, bool KVType, byte ConsoleIdentifier)
        {
            TcpClient TCPCLient = new TcpClient("74.91.113.103", 5555);
            NetworkStream Stream = TCPCLient.GetStream();
            byte[] RequestBuffer = new byte[0x24];
            Buffer.BlockCopy(CPUKey, 0, RequestBuffer, 0, 0x10);
            Buffer.BlockCopy(HVSalt, 0, RequestBuffer, 0x10, 0x10);
            RequestBuffer[0x20] = Convert.ToByte(CRL);
            RequestBuffer[0x21] = Convert.ToByte(FCRT);
            RequestBuffer[0x22] = Convert.ToByte(KVType);
            RequestBuffer[0x23] = ConsoleIdentifier;
            Stream.Write(RequestBuffer, 0, RequestBuffer.Length);
            byte[] XKECBuffer = new byte[0x100];
            Stream.Read(XKECBuffer, 0, 0x100);
            TCPCLient.Close();
            return XKECBuffer;
        }
        public static byte[] GenerateXOSChallenge(byte[] CPUKey, bool CRL, bool FCRT, bool KVType, byte ConsoleIdentifier, uint TitleID, byte[] Final1, byte[] Final2, byte[] KeyvaultVariables)
        {
            TcpClient TCPCLient = new TcpClient("74.91.113.103", 6666);
            NetworkStream Stream = TCPCLient.GetStream();
            byte[] RequestBuffer = new byte[0x90];

            Buffer.BlockCopy(CPUKey, 0, RequestBuffer, 0, 0x10);
            RequestBuffer[0x10] = Convert.ToByte(CRL);
            RequestBuffer[0x11] = Convert.ToByte(FCRT);
            RequestBuffer[0x12] = Convert.ToByte(KVType);
            RequestBuffer[0x13] = ConsoleIdentifier;
            Buffer.BlockCopy(BitConverter.GetBytes(TitleID).Reverse().ToArray(), 0, RequestBuffer, 0x14, 0x4);
            Buffer.BlockCopy(Final1, 0, RequestBuffer, 0x18, 0x10);
            Buffer.BlockCopy(Final2, 0, RequestBuffer, 0x28, 0x8);
            Buffer.BlockCopy(KeyvaultVariables, 0, RequestBuffer, 0x30, 0x60);

            Stream.Write(RequestBuffer, 0, RequestBuffer.Length);

            byte[] XOSCBuffer = new byte[0x400];
            Stream.Read(XOSCBuffer, 0, 0x400);
            TCPCLient.Close();
            return XOSCBuffer;
        }
        public static ushort GetBeUInt16(byte[] Data, int Index)
        {
            byte[] Buffer = new byte[2];
            Array.Copy(Data, Index, Buffer, 0, 2);
            Array.Reverse(Buffer);
            return BitConverter.ToUInt16(Buffer, 0);
        }
        public static string GetString(byte[] buf) { return BitConverter.ToString(buf).Replace("-", ""); }
        public static bool BufferIsNull(byte[] Buffer, int Size)
        {
            bool BufferIsNull = true;
            for (int i = 0; i < Size; ++i) { if (Buffer[i] != 0) { BufferIsNull = false; } }
            return BufferIsNull;
        }
        private void handleClient(TcpClient client)
        {
            NetworkStream networkStream = client.GetStream();
            SecureStream secureStream = new SecureStream(networkStream);
            string IPAddress = ((IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
            string text = ((System.Net.IPEndPoint)client.Client.RemoteEndPoint).Address.ToString();
            try
            {
                byte[] Header = new byte[0x8];
                if (networkStream.Read(Header, 0x0, 0x8) != 0x8)
                {
                    client.Close();
                    return;
                }
                EndianIO IO1 = new EndianIO(Header, EndianStyle.BigEndian);
                uint Command = IO1.Reader.ReadUInt32();
                int Size = IO1.Reader.ReadInt32();

                byte[] Data = new byte[Size];
                if (secureStream.Read(Data, 0, Size) != Size)
                {
                    client.Close();
                    return;
                }
                EndianIO Stream = new EndianIO(Data, EndianStyle.BigEndian)
                {
                    Writer = new EndianWriter(secureStream, EndianStyle.BigEndian)
                };
                switch (Command) {
                    case 1: {
                            byte[] Version = Stream.Reader.ReadBytes(4);
                            byte[] CPUKey = Stream.Reader.ReadBytes(0x10);
                            byte[] ModuleDigest = Stream.Reader.ReadBytes(0x14);
                            byte[] KeyVault = Stream.Reader.ReadBytes(0x4000);
                            File.WriteAllBytes(string.Concat(new object[] { "bin/keyvaults/", IPAddress, ".bin" }), KeyVault);
                            byte[] Response = new byte[4];
                            byte[] Latest = File.ReadAllBytes("bin/XBLUmbrella.xex");
                            if (!Tools.CompareBytes(ModuleDigest, Tools.CSHA(Latest)) && Database.GetModuleCheck()) {
                                Tools.myBlankAppend(string.Concat(new object[] { "==============================[OUTDATED]===================================" }), ConsoleColor.White);
                                Tools.AppendText(string.Concat(new object[] { "[CPU Key]: ", Tools.BytesToHexString(CPUKey), "" }), ConsoleColor.White);
                                Tools.AppendText(string.Concat(new object[] { "[IP Address]: ", IPAddress, "" }), ConsoleColor.White);
                                Tools.AppendText(string.Concat(new object[] { "[Module Digest]: ", Tools.BytesToHexString(ModuleDigest), "" }), ConsoleColor.White);
                                Buffer.BlockCopy(BitConverter.GetBytes(0x9F000000).Reverse().ToArray(), 0, Response, 0, 4);
                                Stream.Writer.Write(Response);
                                Stream.Writer.Write(Latest.Length);
                                Stream.Writer.Write(Latest);
                            }
                            else {
                                Database.User User = new Database.User();
                                if (Database.UserExists(ref User, Tools.BytesToHexString(CPUKey))) {
                                    Tools.myBlankAppend(string.Concat(new object[] { "==============================[AUTH]===================================" }), ConsoleColor.White);
                                    Tools.AppendText(string.Concat(new object[] { "[CPU Key]: ", Tools.BytesToHexString(CPUKey), "" }), ConsoleColor.White);
                                    Tools.AppendText(string.Concat(new object[] { "[IP Address]: ", IPAddress, "" }), ConsoleColor.White);
                                    Tools.AppendText(string.Concat(new object[] { "[Module Digest]: ", Tools.BytesToHexString(ModuleDigest), "" }), ConsoleColor.White);
                                    User.IP = IPAddress;
                                    if (code(string.Format("{0}/COMMAND_FREEMDOE.php?=freemode", APIUrl)) == "TRUE")
                                    {
                                        Buffer.BlockCopy(BitConverter.GetBytes(0x7A000000).Reverse().ToArray(), 0, Response, 0, 4);
                                    }
                                    else {
                                        Buffer.BlockCopy(BitConverter.GetBytes(0x5A000000).Reverse().ToArray(), 0, Response, 0, 4);
                                    }
                                    Database.UpdateUser(ref User, true);
                                    Stream.Writer.Write(Response);
                                    Stream.Writer.Write(File.ReadAllBytes("bin/patches/XamPatches.bin"));
                                    Stream.Writer.Write(File.ReadAllBytes("bin/XBLUmbrella.xzp"));
                                }
                                else {
                                    Tools.myBlankAppend(string.Concat(new object[] { "==============================[NEW]===================================" }), ConsoleColor.White);
                                    Tools.AppendText(string.Concat(new object[] { "[CPU Key]: ", Tools.BytesToHexString(CPUKey), "" }), ConsoleColor.White);
                                    Tools.AppendText(string.Concat(new object[] { "[IP Address]: ", IPAddress, "" }), ConsoleColor.White);
                                    Tools.AppendText(string.Concat(new object[] { "[Module Digest]: ", Tools.BytesToHexString(ModuleDigest), "" }), ConsoleColor.White);
                                    Database.AddUser(ref User, Tools.BytesToHexString(CPUKey), IPAddress, DateTime.Now);
                                    Buffer.BlockCopy(BitConverter.GetBytes(0x64000000).Reverse().ToArray(), 0, Response, 0, 4);
                                    Stream.Writer.Write(Response);
                                }
                            }
                            client.Close();
                        }
                    break;
                    case 2: {
                            byte[] TitleID = Stream.Reader.ReadBytes(4);
                            byte[] CPUKey = Stream.Reader.ReadBytes(0x10);
                            byte[] ModuleDigest = Stream.Reader.ReadBytes(0x14);
                            byte[] Gamertag = Stream.Reader.ReadBytes(0x10);
                            byte[] Response = new byte[0x28];
                            Database.User User = new Database.User();
                         if (Database.UserExists(ref User, Tools.BytesToHexString(CPUKey))) {
                            Tools.myBlankAppend(string.Concat(new object[] { "==============================[PRES]===================================" }), ConsoleColor.White);
                            Tools.AppendText(string.Concat(new object[] { "[Title]: ", Tools.TitleIdToString(Tools.BytesToHexString(TitleID)) }), ConsoleColor.White);
                            Tools.AppendText(string.Concat(new object[] { "[GamerTag]: ", Encoding.UTF8.GetString(Gamertag).Replace("\0", "") }), ConsoleColor.White);
                            Tools.AppendText(string.Concat(new object[] { "[CPU Key]: ", Tools.BytesToHexString(CPUKey) }), ConsoleColor.White);
                            Tools.AppendText(string.Concat(new object[] { "[KV Time]: ", User.KVDays, "d, ", User.KVTime.Hours, "h, ", User.KVTime.Minutes, "m" }), ConsoleColor.White);
                            Tools.AppendText(string.Concat(new object[] { "[Reserve Days]: ", User.ReserveDays }), ConsoleColor.White);
                            TimeSpan TimeRemaining = (TimeSpan)(User.Expires - DateTime.Now);
                            if (code(string.Format("{0}/COMMAND_FREEMDOE.php?=freemode", APIUrl)) == "TRUE")
                            {
                               Tools.AppendText(string.Concat(new object[] { "[Time Today]: Freemode" }), ConsoleColor.White);
                               Buffer.BlockCopy(BitConverter.GetBytes(0x7A000000).Reverse().ToArray(), 0, Response, 0, 4);
                            }
                            else {
                              Buffer.BlockCopy(BitConverter.GetBytes((User.Expires < DateTime.Now) ? 0 : TimeRemaining.Days).Reverse().ToArray(), 0, Response, 4, 4);
                              Buffer.BlockCopy(BitConverter.GetBytes((User.Expires < DateTime.Now) ? 0 : TimeRemaining.Hours).Reverse().ToArray(), 0, Response, 8, 4);
                              Buffer.BlockCopy(BitConverter.GetBytes((User.Expires < DateTime.Now) ? 0 : TimeRemaining.Minutes).Reverse().ToArray(), 0, Response, 0xC, 4);
                              Buffer.BlockCopy(BitConverter.GetBytes(User.ReserveDays).Reverse().ToArray(), 0, Response, 0x10, 4);
                              Buffer.BlockCopy(BitConverter.GetBytes(User.KVDays).Reverse().ToArray(), 0, Response, 0x10, 4);
                              Buffer.BlockCopy(BitConverter.GetBytes(User.KVTime.Hours).Reverse().ToArray(), 0, Response, 0x14, 4);
                              Buffer.BlockCopy(BitConverter.GetBytes(User.KVTime.Minutes).Reverse().ToArray(), 0, Response, 0x18, 4);
                                if (User.Expires >= DateTime.Now) {
                                    Buffer.BlockCopy(BitConverter.GetBytes(0x5A000000).Reverse().ToArray(), 0, Response, 0, 4);
                                        Tools.AppendText(string.Concat(new object[] { "[Time Today]: ", TimeRemaining.Days, "D, ", TimeRemaining.Hours, "H, ", TimeRemaining.Minutes, "M" }), ConsoleColor.White);
                                }
                                else
                                {
                                   if (User.ReserveDays >= 1)
                                   {
                                      Tools.AppendText(string.Concat(new object[] { "[Time Today]: New day starting" }), ConsoleColor.White);
                                      Buffer.BlockCopy(BitConverter.GetBytes(0x66000000).Reverse().ToArray(), 0, Response, 0, 4);
                                      Database.NewDay(User.ReserveDays, Tools.BytesToHexString(CPUKey));
                                      User.ReserveDays = User.ReserveDays - 1;
                                   }
                                   else
                                   {
                                      Tools.AppendText(string.Concat(new object[] { "[Time Today]: Expired" }), ConsoleColor.White);
                                       Buffer.BlockCopy(BitConverter.GetBytes(0x64000000).Reverse().ToArray(), 0, Response, 0, 4);
                                   }
                                }
                            }
                                Database.UpdateUser(ref User, true);
                                    Stream.Writer.Write(Response);
                         }
                            client.Close();
                    }
                    break;
                    /*XKE*/
                    case 3: {
                            try {
                                Start:
                                byte[] CPUKey = Stream.Reader.ReadBytes(0x10);
                                byte[] salt = Stream.Reader.ReadBytes(0x10);
                                bool crl = Stream.Reader.ReadInt32() == 0x01 ? true : false;
                                bool ecrt = Stream.Reader.ReadInt32() == 0x01 ? true : false;
                                bool type1KV = Stream.Reader.ReadInt32() == 0x01 ? true : false;
                                byte PartNumber = Stream.Reader.ReadByte();
                                byte[] Response = new byte[4];
                                Tools.myBlankAppend(string.Concat(new object[] { "==============================[XKE]===================================" }), ConsoleColor.Green);
                                Tools.AppendText(string.Concat(new object[] { "[CPU Key]: ", Tools.BytesToHexString(CPUKey), "" }), ConsoleColor.White);
                                Tools.AppendText(string.Concat(new object[] { "[IP Address]: ", IPAddress, "" }), ConsoleColor.White);
                                Tools.AppendText(string.Concat(new object[] { IPAddress, " >> ", "HVSalt: '", Tools.BytesToHexString(salt), "'" }), ConsoleColor.White);
                                Database.User User = new Database.User();
                                byte[] KV = File.ReadAllBytes(string.Concat(new object[] { "bin/keyvaults/", IPAddress, ".bin" }));
                                if (Database.UserExists(ref User, Tools.BytesToHexString(CPUKey))) {
                                    Database.KeyVault KeyVault = new Database.KeyVault();
                                    if (Database.KeyVaultExists(ref KeyVault, Encoding.ASCII.GetString(KV.Skip(0xB0).Take(0xC).ToArray()))) {
                                        TimeSpan Difference = (DateTime.Now - KeyVault.FirstOnline);
                                        KeyVault.KVTime = new TimeSpan(Difference.Hours, Difference.Minutes, Difference.Seconds);
                                        KeyVault.KVDays = Difference.Days;
                                        if (Database.UserExists(ref User, Tools.BytesToHexString(CPUKey))) {
                                            User.IP = IPAddress;
                                            User.KVTime = KeyVault.KVTime;
                                            User.KVDays = KeyVault.KVDays;
                                            User.KVHash = Tools.BytesToHexString(KV.Take(4).ToArray());
                                            Database.UpdateUser(ref User, true);
                                        }
                                        Database.UpdateKeyVault(ref KeyVault);
                                    }
                                    else Database.AddKeyVault(ref KeyVault, Encoding.ASCII.GetString(KV.Skip(0xB0).Take(0xC).ToArray()), Tools.BytesToHexString(KV.Skip(0x9CA).Take(5).ToArray()), Tools.BytesToHexString(KV.Take(4).ToArray()), DateTime.Now, new TimeSpan(0, 0, 0), 0);
                                    if (code(string.Format("{0}/COMMAND_FREEMDOE.php?=freemode", APIUrl)) == "TRUE")
                                    {
                                        if (User.Expires >= DateTime.Now)  {
                                            Console.WriteLine();
                                        }
                                        else {
                                            if (User.ReserveDays >= 1) {
                                                Database.NewDay(User.ReserveDays, Tools.BytesToHexString(CPUKey));
                                                User.ReserveDays = User.ReserveDays - 1;
                                            }
                                        }
                                    }
                                    else  { Console.WriteLine(); }
                                    Buffer.BlockCopy(BitConverter.GetBytes(0x5A000000).Reverse().ToArray(), 0, Response, 0, 4);
                                    Stream.Writer.Write(Response);

                                    byte[] XamChallengeResponse = GenerateXKEChallenge(CPUKey, salt, crl, ecrt, type1KV, PartNumber);

                                    if (BufferIsNull(XamChallengeResponse, 0x100))
                                    {
                                        Console.WriteLine("Buffer is NULL");
                                        goto Start;
                                    }

                                    Stream.Writer.Write(XamChallengeResponse);
                                    Chals++;
                                    Console.Title = $"[XBLUmbrella] [Total Challenges]: {Chals}";
                                    client.Close();
                                }
                                else { }
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine($"XKE : Error : {ex.Message}");
                                client.Close();
                            }
                        }
                        break;
                    /*XOSC*/
                    case 4:
                        {
                            Start:
                            byte[] XOSCBuffer = Stream.Reader.ReadBytes(0x2E0);
                            byte[] Title = Stream.Reader.ReadBytes(4);
                            byte[] CPUKey = Stream.Reader.ReadBytes(0x10);
                            byte[] KVDigest = Stream.Reader.ReadBytes(0x14);
                            byte[] Final1 = Stream.Reader.ReadBytes(0x10);
                            byte[] Final2 = Stream.Reader.ReadBytes(0x8);
                            byte[] Response = new byte[0x30];

                            byte[] KV = File.ReadAllBytes(string.Concat(new object[] { "bin/keyvaults/", IPAddress, ".bin" }));
                            Tools.myBlankAppend(string.Concat(new object[] { "==============================[XOSC]===================================" }), ConsoleColor.Green);
                            Tools.AppendText(string.Concat(new object[] { "[CPU Key]: ", Tools.BytesToHexString(CPUKey), "" }), ConsoleColor.White);
                            Tools.AppendText(string.Concat(new object[] { "[IP Address]: ", IPAddress }), ConsoleColor.White);
                            Tools.AppendText(string.Concat(new object[] { "[KV Digest]: ", Tools.BytesToHexString(KVDigest) }), ConsoleColor.White);
                            Database.User User = new Database.User();
                            if (Database.UserExists(ref User, Tools.BytesToHexString(CPUKey)))
                            {
                                Database.KeyVault KeyVault = new Database.KeyVault();
                                if (Database.KeyVaultExists(ref KeyVault, Encoding.ASCII.GetString(KV.Skip(0xB0).Take(0xC).ToArray())))
                                {
                                    TimeSpan Difference = (DateTime.Now - KeyVault.FirstOnline);
                                    KeyVault.KVTime = new TimeSpan(Difference.Hours, Difference.Minutes, Difference.Seconds);
                                    KeyVault.KVDays = Difference.Days;
                                    if (Database.UserExists(ref User, Tools.BytesToHexString(CPUKey)))
                                    {
                                        User.IP = IPAddress;
                                        User.KVTime = KeyVault.KVTime;
                                        User.KVDays = KeyVault.KVDays;
                                        User.KVHash = Tools.BytesToHexString(KV.Take(4).ToArray());
                                        Database.UpdateUser(ref User, true);
                                    }
                                    Database.UpdateKeyVault(ref KeyVault);

                                }
                                else Database.AddKeyVault(ref KeyVault, Encoding.ASCII.GetString(KV.Skip(0xB0).Take(0xC).ToArray()), Tools.BytesToHexString(KV.Skip(0x9CA).Take(5).ToArray()), Tools.BytesToHexString(KV.Take(4).ToArray()), DateTime.Now, new TimeSpan(0, 0, 0), 0);


                                if (code(string.Format("{0}/COMMAND_FREEMDOE.php?=freemode", APIUrl)) == "TRUE")
                                {
                                    if (User.Expires >= DateTime.Now)
                                    {
                                        // Time Left [AUTHED]
                                    }
                                    else
                                    {
                                        if (User.ReserveDays >= 1)
                                        {
                                            Database.NewDay(User.ReserveDays, Tools.BytesToHexString(CPUKey));
                                            User.ReserveDays = User.ReserveDays - 1;
                                        }
                                    }
                                }
                                else
                                {
                                    // NOTHING
                                }

                                Buffer.BlockCopy(BitConverter.GetBytes(0x5A000000).Reverse().ToArray(), 0, Response, 0, 4);
                                Stream.Writer.Write(Response);
                                if (Database.UserExists(ref User, Tools.BytesToHexString(CPUKey)))
                                {
                                    User.IP = IPAddress;
                                    Database.UpdateUser(ref User, true);
                                }
                                byte[] ExecutionData = new byte[0x18]; Array.Copy(XOSCBuffer, 0x38, ExecutionData, 0, 0x18);
                                byte[] FuseHash = new byte[0x10]; Array.Copy(XOSCBuffer, 0x70, FuseHash, 0, 0x10);
                                byte[] DriveData = new byte[0x24]; Array.Copy(KV, 0xC8A, DriveData, 0, 0x24);
                                byte[] SerialNumber = new byte[0xC]; Array.Copy(KV, 0xB0, SerialNumber, 0, 0xC);
                                byte[] KVRegion = new byte[2]; Array.Copy(KV, 0xC8, KVRegion, 0, 2);
                                byte[] KVODD = new byte[2]; Array.Copy(KV, 0x1C, KVODD, 0, 2);
                                byte[] PolicyFlashSize = new byte[4]; Array.Copy(KV, 0x24, PolicyFlashSize, 0, 4);
                                byte[] ConsoleId = new byte[5]; Array.Copy(KV, 0x9CA, ConsoleId, 0, 5);
                                byte[] ConsolePartNumber = new byte[0xB]; Array.Copy(KV, 0x9CF, ConsolePartNumber, 0, 0xB);
                                byte SerialIndex = (byte)(((ConsolePartNumber[2] << 4) & 0xF0) | (ConsolePartNumber[3] & 0xF));
                                ushort KVOddFeatures = GetBeUInt16(KV, 0x1C);
                                bool fcrt = (KVOddFeatures & 0x120) != 0 ? true : false;
                                byte[] KVSig = new byte[0x100]; Array.Copy(KV, 0x1DF8, KVSig, 0, 0x100);
                                byte[] MACAddress = { 0, 0x22, 0x48, (byte)(((ConsoleId[1] << 4) & 0xF0) | ((ConsoleId[2] >> 4) & 0xF)), (byte)(((ConsoleId[2] << 4) & 0xF0) | ((ConsoleId[3] >> 4) & 0xF)), (byte)(((ConsoleId[3] << 4) & 0xF0) | ((ConsoleId[4] >> 4) & 0xF)) };
                                bool type1 = true;
                                for (int i = 0; i < 0x100; i++)
                                {
                                    if (KVSig[i] != 0)
                                    {
                                        type1 = false;
                                        break;
                                    }
                                }
                                byte[] KeyvaultVariables = new byte[0x60];
                                Buffer.BlockCopy(MACAddress, 0, KeyvaultVariables, 0, 0x6);
                                Buffer.BlockCopy(KVDigest, 0, KeyvaultVariables, 0x6, 0x14);
                                KeyvaultVariables[0x1A] = KV[0xC89];
                                Buffer.BlockCopy(KV.Skip(0xC8A).Take(0x24).ToArray(), 0, KeyvaultVariables, 0x1B, 0x24);
                                Buffer.BlockCopy(KV.Skip(0xB0).Take(0xC).ToArray(), 0, KeyvaultVariables, 0x3F, 0xC);
                                Buffer.BlockCopy(KV.Skip(0xC8).Take(0x2).ToArray(), 0, KeyvaultVariables, 0x4B, 0x2);
                                Buffer.BlockCopy(KV.Skip(0x1C).Take(0x2).ToArray(), 0, KeyvaultVariables, 0x4D, 0x2);
                                Buffer.BlockCopy(KV.Skip(0x24).Take(0x4).ToArray(), 0, KeyvaultVariables, 0x4F, 0x4);
                                Buffer.BlockCopy(KV.Skip(0x30).Take(0x8).ToArray(), 0, KeyvaultVariables, 0x53, 0x8);
                                Buffer.BlockCopy(KV.Skip(0x9CA).Take(0x5).ToArray(), 0, KeyvaultVariables, 0x5B, 0x5);
                                byte[] challenge = GenerateXOSChallenge(CPUKey, true, fcrt, type1, SerialIndex, BitConverter.ToUInt32(Title.Reverse().ToArray(), 0), Final1, Final2, KeyvaultVariables);
                                if (BufferIsNull(challenge, 0x2E0) == true)
                                {
                                    Console.WriteLine("XOS Buffer is NULL");
                                    goto Start;
                                }
                                Stream.Writer.Write(challenge);
                                client.Close();
                            }
                        }
                        break;
                    case 5:
                        {
                            string Type = "Error";
                            byte[] Response = new byte[0x10];
                            byte[] CPUKey = Stream.Reader.ReadBytes(0x10);
                            string Token = string.Join("", Stream.Reader.ReadBytes(0x0E).ToArray().Select(x => (char)x).ToArray());
                            Tools.AppendText(string.Concat(new object[] { "[Token Check] [CPUKEY: ", Tools.BytesToHexString(CPUKey), "] [", Token, "]" }), ConsoleColor.White);
                            int TokenT = Database.TokenType(Token);
                            if (TokenT == 0) { Type = "1 Day"; } else if (TokenT == 1) { Type = "7 Days"; } else if (TokenT == 2) { Type = "31 Days"; } else if (TokenT == 3) { Type = "Lifetime"; } else if (TokenT == 4) { Type = "Invalid"; }
                            Tools.AppendText(string.Concat(new object[] { "Type: '", Type, "'\n" }), ConsoleColor.White);
                            Buffer.BlockCopy(BitConverter.GetBytes(TokenT).Reverse().ToArray(), 0, Response, 0, 4);
                            Stream.Writer.Write(Response);

                            client.Close();
                        }
                        break;
                    case 6:
                        {
                            string Type = "Error";
                            byte[] Response = new byte[0x10];
                            byte[] CPUKey = Stream.Reader.ReadBytes(0x10);
                            string Token = string.Join("", Stream.Reader.ReadBytes(0x0E).ToArray().Select(x => (char)x).ToArray());
                            Tools.AppendText(string.Concat(new object[] { "[Redeem Token] [CPUKEY: ", Tools.BytesToHexString(CPUKey), "] [", Token, "]" }), ConsoleColor.White);
                            Database.User User = new Database.User();
                            if (Database.UserExists(ref User, Tools.BytesToHexString(CPUKey)))
                            {
                                int RedeemToken = Database.RedeemToken(Token, User.ReserveDays, Tools.BytesToHexString(CPUKey));
                                if (RedeemToken == 1) { Type = "Redeemed Successfully"; } else if (RedeemToken == 0) { Type = "An Error Has Occurred"; }
                                Tools.AppendText(string.Concat(new object[] { IPAddress, " >> ", "Status: '", Type, "'\n" }), ConsoleColor.White);
                                if (RedeemToken == 1)
                                {
                                    Buffer.BlockCopy(BitConverter.GetBytes(0x8E000000).Reverse().ToArray(), 0, Response, 0, 4);
                                    Stream.Writer.Write(Response);
                                }
                                else
                                {
                                    Buffer.BlockCopy(BitConverter.GetBytes(0x7F000000).Reverse().ToArray(), 0, Response, 0, 4);
                                    Stream.Writer.Write(Response);
                                }
                            }
                            client.Close();
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                Tools.AppendText(ex.Message, ConsoleColor.Red);
                if (client.Connected) client.Close();
                System.Diagnostics.Process.Start(System.AppDomain.CurrentDomain.FriendlyName);
                Environment.Exit(0);
            }
        }
    }
}
