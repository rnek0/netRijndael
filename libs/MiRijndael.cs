using System;
using System.Security.Cryptography;

namespace Rijndael.libs
{
    public class MiRijndael
    {
        // Le salt pour la clé de chiffrement (a toi de voir pour plus complexe ou pour demander en arg).
        private static byte[] saltArray = new byte[8] { 1, 2, 3, 4, 5, 6, 7, 8 };

        // Clé generée a l'encriptation. = byte[32];
        private static byte[] clepseudoaleatoire;

        // Encripte après mise en forme de la clé.

        public static byte[] Encriptar(string strEncriptar, string strPK)
        {
            clepseudoaleatoire = (new Rfc2898DeriveBytes(strPK, saltArray)).GetBytes(32);
            return Encriptar(strEncriptar, clepseudoaleatoire);
        }

        // Prends la chaine passée en paramettre et la clé de 32 bytes mise en forme et crypte.         
        public static byte[] Encriptar(string strEncriptar, byte[] bytPK)
        {
            byte[] encrypted = null;
            byte[] returnValue = null;

            using (System.Security.Cryptography.Aes miRijndael = Aes.Create())
            {
                miRijndael.Key = bytPK;
                miRijndael.GenerateIV();

                byte[] toEncrypt = System.Text.Encoding.Unicode.GetBytes(strEncriptar);
                encrypted = (miRijndael.CreateEncryptor()).TransformFinalBlock(toEncrypt, 0, toEncrypt.Length);

                // On recupère le IV pour un decriptage futur (ajouté a la chaine cryptée).
                returnValue = new byte[miRijndael.IV.Length + encrypted.Length];
                miRijndael.IV.CopyTo(returnValue, 0);
                encrypted.CopyTo(returnValue, miRijndael.IV.Length);
            }

            return returnValue;
        }

        // Decripte.
        public static string Desencriptar(byte[] bytDesEncriptar, byte[] bytPK)
        {
            string returnValue = string.Empty;
            System.Security.Cryptography.Aes miRijndael = Aes.Create();

            if(bytDesEncriptar.Length > 0) // TODO: verifier la longueur des arrays !
            {
                byte[] tempArray = new byte[miRijndael.IV.Length];
                byte[] encrypted = new byte[bytDesEncriptar.Length - miRijndael.IV.Length];   
            try
            {
                miRijndael.Key = bytPK;
                //Recupère le IV dans la chaine cryptée.
                Array.Copy(bytDesEncriptar, tempArray, tempArray.Length);
                Array.Copy(bytDesEncriptar, tempArray.Length, encrypted, 0, encrypted.Length);
                miRijndael.IV = tempArray;
                
                returnValue = System.Text.Encoding.Unicode.GetString((miRijndael.CreateDecryptor()).TransformFinalBlock(encrypted, 0, encrypted.Length));
            }
            catch { }
            finally { miRijndael.Dispose(); }
            }
            else
            {return "erreur inconnue !";}
            return returnValue;
        }
        
        // Decripte a partir de la clé mise en forme. 
        public static string Desencriptar(byte[] bytDesEncriptar, string strPK)
        {
            clepseudoaleatoire = (new Rfc2898DeriveBytes(strPK, saltArray)).GetBytes(32);
            return Desencriptar(bytDesEncriptar, clepseudoaleatoire);
        }
    }
}