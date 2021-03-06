using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;

namespace _4_darbas
{
    public partial class Form1 : Form
    {
        string password = "Test";
        string path = "C:\\Users\\Hunter\\Desktop\\IS\\Testinis Folderis";
        string currentline = null;
        string passaword = null;
        bool login = false;
        public Form1()
        {
            InitializeComponent();
        }
        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (login)
            {
                try
                {
                    Encrypt(path + "\\Magic.txt", password);
                    File.Delete(path + "\\Magic.txt");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine(ex.Message);
                }
            }
        }

        private void Encrypt(string inputFile, string password)
        {
            //generate random salt
            byte[] salt = GenerateRandomSalt();

            //create output file name
            using FileStream fsCrypt = new FileStream(inputFile + ".aes", FileMode.Create);

            //convert password string to byte arrray
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            //Set Rijndael symmetric encryption algorithm
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;

            //"What it does is repeatedly hash the user password along with the salt." High iteration counts.
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);

            AES.Mode = CipherMode.CFB;

            // write salt to the begining of the output file, so in this case can be random every time
            fsCrypt.Write(salt, 0, salt.Length);

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);

            FileStream fsIn = new FileStream(inputFile, FileMode.Open);

            //create a buffer (1mb) so only this amount will allocate in the memory and not the whole file
            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = fsIn.Read(buffer, 0, buffer.Length)) > 0)
                {
                    Application.DoEvents(); // -> for responsive GUI, using Task will be better!
                    cs.Write(buffer, 0, read);
                }

                // Close up
                fsIn.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
            }
        }

        private void Decrypt(string inputFile, string password)
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[32];

            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);

            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;
            string outputFile = inputFile.Substring(0, inputFile.Length - 4);

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);

            FileStream fsOut = new FileStream(outputFile, FileMode.Create);

            int read;
            byte[] buffer = new byte[1048576];

            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    Application.DoEvents();
                    fsOut.Write(buffer, 0, read);
                }
            }
            catch (CryptographicException ex_CryptographicException)
            {
                Console.WriteLine("CryptographicException error: " + ex_CryptographicException.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: " + ex.Message);
            }

            try
            {
                cs.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error by closing CryptoStream: " + ex.Message);
            }
            finally
            {
                fsOut.Close();
                fsCrypt.Close();
            }
        }
        public static byte[] GenerateRandomSalt()
        {
            byte[] data = new byte[32];

            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                for (int i = 0; i < 10; i++)
                {
                    rng.GetBytes(data);
                }
            }

            return data;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (!String.IsNullOrWhiteSpace(Comment_txt.Text) &&
                !String.IsNullOrWhiteSpace(Name_txt.Text) &&
                !String.IsNullOrWhiteSpace(Password_txt.Text) &&
                !String.IsNullOrWhiteSpace(URL_App_txt.Text)
                )
            {
                bool temp = false;

                string line;
                using StreamReader file = new StreamReader(path + "\\Magic.txt");
                while ((line = file.ReadLine()) != null)
                {
                    string[] split = line.Split(';');
                    if (split[0] == Name_txt.Text)
                    {
                        temp = true;
                        MessageBox.Show("Pavadinimas toks jau egzistuoja");
                    }
                }
                file.Close();
                if (!temp)
                {
                    using (StreamWriter w = File.AppendText(path + "\\Magic.txt"))
                    {
                        w.WriteLine(String.Format("{0};{1};{2};{3}", Name_txt.Text, EncryptText(Password_txt.Text), URL_App_txt.Text, Comment_txt.Text));
                        MessageBox.Show("sėkmingai išsaugota");
                        Comment_txt.Text = "";
                        Name_txt.Text = "";
                        Password_txt.Text = "";
                        URL_App_txt.Text = "";
                    }
                }
            }
            else
            {
                MessageBox.Show("Visi langai turi būti užpildyti");
            }
        }

        private string EncryptText(string text)
        {
            // Nesifruotas tekstaspaverciamas i baitus
            byte[] tekstas = Encoding.UTF8.GetBytes(text);
            RijndaelManaged aes = new RijndaelManaged();
            // Modas ecb
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = 128;

            // Sukuria sifratoriu
            using (ICryptoTransform sifratorius = aes.CreateEncryptor(Encoding.UTF8.GetBytes("ananasasananasas"), null))
            {
                // Sifruojam teksta
                byte[] sifruotasTekstas = sifratorius.TransformFinalBlock(tekstas, 0, tekstas.Length);
                // Nutraukiam darba
                sifratorius.Dispose();
                // Grazinam sifruota teksta string formatu
                return Convert.ToBase64String(sifruotasTekstas);
            }
        }
        private string DecryptText(string text)
        {
            // Konvertuoja teksta i baitus
            byte[] sifruotasTekstas = Convert.FromBase64String(text);
            RijndaelManaged aes = new RijndaelManaged();
            // Nustatom rakto dydi
            aes.KeySize = 128;
            aes.Padding = PaddingMode.PKCS7;
            // Nuastatom moda i ecb
            aes.Mode = CipherMode.ECB;

            // Sukuria desifratoriu
            using (ICryptoTransform desifratorius = aes.CreateDecryptor(Encoding.UTF8.GetBytes("ananasasananasas"), null))
            {
                byte[] desifruotasTekstas = desifratorius.TransformFinalBlock(sifruotasTekstas, 0, sifruotasTekstas.Length);
                // Nutraukia desifravimo darba
                desifratorius.Dispose();
                // Grazinam Desifruota teksta string formatu
                return Encoding.UTF8.GetString(desifruotasTekstas);
            }
        }

        private void FindName_btn_Click(object sender, EventArgs e)
        {
            string line;
            using StreamReader file = new StreamReader(path + "\\Magic.txt");
            while ((line = file.ReadLine()) != null)
            {
                string[] split = line.Split(';');
                if (split[0] == FindName_txt.Text)
                {
                    currentline = line;
                    Name_lbl.Text = split[0];
                    Password_lbl.Text = split[1];
                    passaword = split[1];
                    URL_lbl.Text = split[2];
                    Comment_lbl.Text = split[3];
                    break;
                }
                else NullLabel();
            }
        }

        private void ChangePassword_btn_Click(object sender, EventArgs e)
        {
            try
            {
                if (!String.IsNullOrWhiteSpace(ChangePassword_txt.Text))
                {
                    try
                    {
                        string newline = String.Format("{0};{1};{2};{3}", Name_lbl.Text, EncryptText(ChangePassword_txt.Text), URL_lbl.Text, Comment_lbl.Text);
                        File.WriteAllText(path + "\\Magic.txt", File.ReadAllText(path + "\\Magic.txt").Replace(currentline, newline));
                        NullLabel();
                        ShowPassword_btn.Text = "Parodyti slaptažodį";
                    }
                    catch { }
                }
                else
                {
                    MessageBox.Show("Langelis negali būti tuščias");
                }
            }
            catch
            {
                MessageBox.Show("Pasirinkite slaptažodį kuri norite pakeisti");
            }

        }
        void NullLabel()
        {
            Name_lbl.Text = null;
            Password_lbl.Text = null;
            URL_lbl.Text = null;
            Comment_lbl.Text = null;
            currentline = null;
            passaword = null;
            ShowPassword_btn.Text = "Parodyti slaptažodį";
        }

        private void DeletePassword_btn_Click(object sender, EventArgs e)
        {
            try
            {
                File.WriteAllText(path + "\\Magic.txt", File.ReadAllText(path + "\\Magic.txt").Replace(currentline, ""));
                ShowPassword_btn.Text = "Parodyti slaptažodį";
                NullLabel();
            }
            catch
            {
                MessageBox.Show("Pasirinkite slaptažodi kuri norite trinti");
            }
        }

        private void ShowPassword_btn_Click(object sender, EventArgs e)
        {
            if (ShowPassword_btn.Text == "Parodyti slaptažodį")
            {
                ShowPassword_btn.Text = "Paslėpti slaptažodį";
                Password_lbl.Text = DecryptText(Password_lbl.Text);
            }
            else
            {
                ShowPassword_btn.Text = "Parodyti slaptažodį";
                Password_lbl.Text = EncryptText(Password_lbl.Text);
            }
        }

        private void RandomPassword_btn_Click(object sender, EventArgs e)
        {

            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[12];
            var random = new Random();

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }

            Password_txt.Text = new String(stringChars);
        }

        private void CopyPassword_btn_Click(object sender, EventArgs e)
        {
            if (passaword != null)
                Clipboard.SetText(DecryptText(passaword));
        }

        private void button2_Click(object sender, EventArgs e)
        {
            try
            {
                login = true;
                groupBox1.Visible = false;
                tabControl1.Visible = true;
                if (File.Exists(path + "\\Magic.txt.aes"))
                {
                    Decrypt(path + "\\Magic.txt.aes", password);
                    File.Delete(path + "\\Magic.txt.aes");
                }
                else
                {
                    File.Create(path + "\\Magic.txt").Close();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.Message);
            }
        }
    }
}
