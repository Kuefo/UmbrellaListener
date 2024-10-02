using System.IO;
namespace Globals {
    public static class Tools {
        public static string BytesToHexString(byte[] Buffer)
        {
            string str = "";
            for (int i = 0; i < Buffer.Length; i++) { str = str + Buffer[i].ToString("X2"); }
            return str;
        }
    }
    public class EndianWriter : BinaryWriter
    {
        private readonly EndianStyle endianStyle;

        public EndianWriter(Stream stream, EndianStyle endianstyle)
            : base(stream)
        {
            this.endianStyle = endianstyle;
        }
    }
    public enum EndianStyle { LittleEndian, BigEndian }
    public class EndianReader : BinaryReader
    {
        private readonly EndianStyle _endianStyle;
        public EndianReader(Stream Stream, EndianStyle EndianStyle) : base(Stream) { this._endianStyle = EndianStyle; }
    }
    public class EndianIO
    {
        private readonly EndianStyle _endianStyle;
        private readonly string _filePath;
        private readonly bool _isFile;
        public EndianIO(System.IO.Stream Stream, EndianStyle EndianStyle)
        {
            this._filePath = string.Empty;
            this._endianStyle = EndianStyle.LittleEndian;
            this._endianStyle = EndianStyle;
            this.Stream = Stream;
            this._isFile = false;
            this.Open();
        }
        public void Open() { this.Open(FileMode.Open); }
        public void Open(FileMode FileMode)
        {
            if (!this.Opened)
            {
                if (this._isFile) { this.Stream = new FileStream(this._filePath, FileMode, FileAccess.ReadWrite); }
                this.Reader = new EndianReader(this.Stream, this._endianStyle);
                this.Writer = new EndianWriter(this.Stream, this._endianStyle);
                this.Opened = true;
            }
        }
        public bool Opened { get; set; }
        public EndianReader Reader { get; set; }
        public System.IO.Stream Stream { get; set; }
        public EndianWriter Writer { get; set; }
    }
}