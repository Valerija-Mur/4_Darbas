using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
namespace _2_Darbas_AES
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Sifravimo_btn_Click(object sender, EventArgs e)
        {
            // Paimam teksta is textbox
            string originalus = Teksats_txt.Text;
            // Priskiriam textboxui sifruota teksta 
            STekstas_txt.Text =
            Sifruojam(originalus);
        }
        private void Desifravimo_btn_Click(object sender, EventArgs e)
        {
            // Paimam teksta is textbox
            string originalus = STekstas_txt.Text;
            // Priskiriam textboxui sifruota teksta 
            Teksats_txt.Text =
            Desifruojam(originalus);
        }
        private void FailoIrasymas_btn_Click(object sender, EventArgs e)
        {
            string originalus = Teksats_txt.Text;
            IssaugojimasFaile(Sifruojam(originalus));
        }

        private void FailoSkaitymas_btn_Click(object sender, EventArgs e)
        {
            string originalus = FailoSkaitymas();
            Teksats_txt.Text = Desifruojam(originalus);
        }
        static string SifruojamTekstaIBaitus_CBC(string tekstas, byte[] Key)
        {
            byte[] sifras;
            byte[] IV;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.GenerateIV();
                IV = aesAlg.IV;
                aesAlg.Padding = PaddingMode.PKCS7;

                aesAlg.Mode = CipherMode.CBC;

                var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Sukuria stream sifravimui
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            // Paraso visa data i stream
                            swEncrypt.Write(tekstas);
                        }
                        sifras = msEncrypt.ToArray();
                    }
                }
            }
            // Sifruoja
            var combinedIvCt = new byte[IV.Length + sifras.Length];
            Array.Copy(IV, 0, combinedIvCt, 0, IV.Length);
            Array.Copy(sifras, 0, combinedIvCt, IV.Length, sifras.Length);

            // Grazina sifruota teksta string pavidalu
            return Convert.ToBase64String(combinedIvCt);

        }
        static string DesifruojamBaitusITeksta_CBC(string sifruotasTekstas, byte[] Key)
        {
            byte[] sifruotasTekstasBaitais = Convert.FromBase64String(sifruotasTekstas);
            string desifruotasTekstas = null;


            using (Aes aesAlg = Aes.Create())
            {
                // Priskiriam rakta
                aesAlg.Key = Key;
                // Sukuriamas vektorius ir nustatomas ilgis
                byte[] IV = new byte[aesAlg.BlockSize / 8];
                byte[] sifras = new byte[sifruotasTekstasBaitais.Length - IV.Length];

                // Keicia
                Array.Copy(sifruotasTekstasBaitais, IV, IV.Length);
                Array.Copy(sifruotasTekstasBaitais, IV.Length, sifras, 0, sifras.Length);

                // Nustatomas Vektoriaus reiksme
                aesAlg.IV = IV;
                // Padingas
                aesAlg.Padding = PaddingMode.PKCS7;
                // Modas
                aesAlg.Mode = CipherMode.CBC;

                // Sukuria desifratoriu
                ICryptoTransform desifratorius = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Sukuria stream desifravimui
                using (var msDecrypt = new MemoryStream(sifras))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, desifratorius, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Skaito desifruotus baitus is desifravimo stream ir ideda i stringa
                            desifruotasTekstas = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return desifruotasTekstas;
        }
        private string SifruojamTekstaIBaitus_ECB(string text, byte[] key)
        {
            // Nesifruotas tekstaspaverciamas i baitus
            byte[] tekstas = Encoding.UTF8.GetBytes(text);
            RijndaelManaged aes = new RijndaelManaged();
            // Modas ecb
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = 128;

            // Sukuria sifratoriu
            using (ICryptoTransform sifratorius = aes.CreateEncryptor(key, null))
            {
                // Sifruojam teksta
                byte[] sifruotasTekstas = sifratorius.TransformFinalBlock(tekstas, 0, tekstas.Length);
                // Nutraukiam darba
                sifratorius.Dispose();
                // Grazinam sifruota teksta string formatu
                return Convert.ToBase64String(sifruotasTekstas);
            }
        }
        private string DesifruojamBaitusITeksta_ECB(string text, byte[] key)
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
            using (ICryptoTransform desifratorius = aes.CreateDecryptor(key, null))
            {
                byte[] desifruotasTekstas = desifratorius.TransformFinalBlock(sifruotasTekstas, 0, sifruotasTekstas.Length);
                // Nutraukia desifravimo darba
                desifratorius.Dispose();
                // Grazinam Desifruota teksta string formatu
                return Encoding.UTF8.GetString(desifruotasTekstas);
            }
        }
        void IssaugojimasFaile(string tekstas)
        {
            using (var sfd = new SaveFileDialog())
            {
                sfd.Filter = "txt files (*.txt)|*.txt";

                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    File.WriteAllText(sfd.FileName, tekstas);
                }
            }
        }
        string FailoSkaitymas()
        {
            var fileContent = string.Empty;
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                openFileDialog.Filter = "txt files (*.txt)|*.txt";
                openFileDialog.RestoreDirectory = true;

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    var fileStream = openFileDialog.OpenFile();

                    using (StreamReader reader = new StreamReader(fileStream))
                    {
                        fileContent = reader.ReadToEnd();
                    }
                }
            }
            return fileContent;
        }
        string Sifruojam(string tekstas)
        {
            try
            {
                string sifras;
                string sifravimas;
                if (Raktas_txt.Text.Length == 16)
                {
                    // Suteikiam rakta is text boxo
                    byte[] key = Encoding.UTF8.GetBytes(Raktas_txt.Text);
                    if (CBC_rbtn.Checked == true)
                    {
                        // Sifruojam 
                        sifravimas = SifruojamTekstaIBaitus_CBC(tekstas, key);
                        // Grazinam baitus paversta i string
                        return sifravimas;
                    }
                    else if (ECB_rbtn.Checked == true)
                    {
                        //  Sifruojam
                        sifras = SifruojamTekstaIBaitus_ECB(tekstas, key);

                        return sifras;
                    }
                    else
                        MessageBox.Show("Pasirinkite tarp CBC ir ECB modų");
                }
                else
                    MessageBox.Show(String.Format("Reikia įvesti 16-os simbolių raktą \nĮvedėte tik {0} simbolių/us", Raktas_txt.Text.Length.ToString()));
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: {0}", ex.Message);
            }
            return null;
        }
        string Desifruojam(string tekstas)
        {
            try
            {
                string desifravimas;
                if (Raktas_txt.Text.Length == 16)
                {
                    // Raktini teksta paverciam i baita
                    var key = Encoding.UTF8.GetBytes(Raktas_txt.Text);
                    if (CBC_rbtn.Checked == true)
                    {
                        // Gauname desifruota teksta                // Konvertuojam FromBase64String, kad nepaasitekstu reiksmes
                        desifravimas = DesifruojamBaitusITeksta_CBC(tekstas, key);
                        // Grazinam verte, kad irasytu i textboxa arba faila
                        return desifravimas;
                    }
                    else if (ECB_rbtn.Checked == true)
                    {
                        // PAduoda sifruota teksta ir rakta
                        desifravimas = DesifruojamBaitusITeksta_ECB(tekstas, key);
                        // Grazinam verte, kad irasytu i textboxa arba faila
                        return desifravimas;
                    }
                    else
                    {
                        MessageBox.Show("Pasirinkite tarp CBC ir ECB modų");
                    }
                }
                else
                {
                    MessageBox.Show(String.Format("Reikia įvesti 16-os simbolių raktą \nĮvedėte tik {0} simbolių/us", Raktas_txt.Text.Length.ToString()));
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error: {0}", ex.Message);
            }
            return null;
        }

    }
}