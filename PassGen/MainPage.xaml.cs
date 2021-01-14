using System;
using System.Globalization;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Xamarin.Forms;
using Xamarin.Essentials;

namespace PassGen
{
  public partial class MainPage : ContentPage
  {
    public MainPage() {
      InitializeComponent();
    }

    private void NewMasterPasswordButton_Clicked(object sender, EventArgs e) {
      MasterPasswordEntry.IsPassword = false;
      MasterPasswordChecksumEntry.IsPassword = false;
      if (MasterPasswordEntry.Text != null && MasterPasswordEntry.Text != "" &&
        (MasterPasswordChecksumEntry.Text == null || MasterPasswordChecksumEntry.Text == "")) {
      } else {
        int PassLength = 16;
        var rxPassLength = new Regex(@"\((\d+)\)");
        var mPassLength = rxPassLength.Match((string)NewMasterPasswordOptionsPicker.SelectedItem);
        if (mPassLength.Success)
          PassLength = int.Parse(mPassLength.Groups[1].Value);
        MasterPasswordEntry.Text = KeyGenerator.GetUniqueKey(PassLength);
      }
      var Key = Encoding.ASCII.GetBytes(MasterPasswordEntry.Text);
      MasterPasswordChecksumEntry.Text = string.Format("{0:X}", Crc16Ccitt(Key));
    }

    private void GeneratePasswordButton_Clicked(object sender, EventArgs e) {
      if (UniqueIdEntry.Text != null && UniqueIdEntry.Text != "" &&
        MasterPasswordEntry.Text != null && MasterPasswordEntry.Text != "" &&
        MasterPasswordChecksumEntry.Text != null && MasterPasswordChecksumEntry.Text != "") {
        var Key = Encoding.ASCII.GetBytes(MasterPasswordEntry.Text);
        ushort KeyChecksum;
        if (ushort.TryParse(MasterPasswordChecksumEntry.Text, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out KeyChecksum) && Crc16Ccitt(Key) == KeyChecksum) {
          var TripleDES = new TripleDESCryptoServiceProvider() { Mode = CipherMode.ECB, Padding = PaddingMode.Zeros, Key = PadWithZeros(Key, 16) }.CreateEncryptor();
          byte[] Input = Encoding.ASCII.GetBytes(UniqueIdEntry.Text);
          byte[] Output = TripleDES.TransformFinalBlock(Input, 0, Input.Length);
          string Text = Convert.ToBase64String(Output);
          NewPasswordEntry.Text = (char.ToUpper(Text[0]) + Text.Substring(1, Math.Min(Text.Length - 1, 15))).Trim('=') + "#";
        } else {
          DisplayAlert("Error", "Invalid checksum for the master password!", "Ok");
        }
      } else {
        DisplayAlert("Error", "Enter valid unique id and master password!", "Ok");
      }
    }

    static byte[] PadWithZeros(byte[] bytes, int length) {
      var padded = new byte[length];
      Array.Copy(bytes, padded, Math.Min(padded.Length, bytes.Length));
      return padded;
    }

    private void ShowNewPasswordButton_Clicked(object sender, EventArgs e) {
      NewPasswordEntry.IsPassword = false;
    }

    private void CopyNewPasswordButton_Clicked(object sender, EventArgs e) {
      Clipboard.SetTextAsync(NewPasswordEntry.Text);
    }

    private ushort Crc16Ccitt(byte[] bytes) {
      const ushort poly = 4129;
      ushort[] table = new ushort[256];
      ushort initialValue = 0x1D0F;
      ushort temp, a;
      ushort crc = initialValue;
      for (int i = 0; i < table.Length; ++i) {
        temp = 0;
        a = (ushort)(i << 8);
        for (int j = 0; j < 8; ++j) {
          if (((temp ^ a) & 0x8000) != 0)
            temp = (ushort)((temp << 1) ^ poly);
          else
            temp <<= 1;
          a <<= 1;
        }
        table[i] = temp;
      }
      for (int i = 0; i < bytes.Length; ++i) {
        crc = (ushort)((crc << 8) ^ table[((crc >> 8) ^ (0xff & bytes[i]))]);
      }
      return crc;
    }

    public class KeyGenerator
    {
      internal static readonly char[] chars =
          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();

      public static string GetUniqueKey(int size) {
        byte[] data = new byte[4 * size];
        using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider()) {
          crypto.GetBytes(data);
        }
        StringBuilder result = new StringBuilder(size);
        for (int i = 0; i < size; i++) {
          var rnd = BitConverter.ToUInt32(data, i * 4);
          var idx = rnd % chars.Length;

          result.Append(chars[idx]);
        }

        return result.ToString();
      }

      public static string GetUniqueKeyOriginal_BIASED(int size) {
        char[] chars =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890".ToCharArray();
        byte[] data = new byte[size];
        using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider()) {
          crypto.GetBytes(data);
        }
        StringBuilder result = new StringBuilder(size);
        foreach (byte b in data) {
          result.Append(chars[b % (chars.Length)]);
        }
        return result.ToString();
      }
    }
  }
}
