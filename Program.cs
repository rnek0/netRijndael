//
// Descripción del cifrado
// https://es.wikipedia.org/wiki/Advanced_Encryption_Standard#Descripci%C3%B3n_del_cifrado
//
using System;
using System.Security.Cryptography;
using System.Text;
using Rijndael.libs;

namespace Rijndael
{
    enum Fais{
        CRIPTE=1,
        DECRIPTE,
        SORTIR,
        ERROR
    }

    class Program
    {
        private static readonly byte[] Salt = new byte[] { 10, 20, 30, 40, 50, 60, 70, 80 };
        private static byte[] CreateKey(string password, int keyBytes = 32)
        {
            const int Iterations = 300;
            var keyGenerator = new Rfc2898DeriveBytes(password, Salt, Iterations);
            return keyGenerator.GetBytes(keyBytes);
        }

        static void Main(string[] args)
        {
            var quit = false;
            Console.WriteLine($" MyRijndael Crypto Sys : {DateTime.Now}");

            var control = 0;
            Aes myAes = Aes.Create();
            myAes.Padding = PaddingMode.PKCS7;

            //myAes.GenerateKey();
            myAes.Key = Convert.FromBase64String("EvptELA276DwhU99jrXcECSdklcMRved2HiqO4k3Vms=");
            //myAes.Key = CreateKey("toto");

            // myAes.IV = CreateKey("toto", 16);
            // Tente de creer toujours le même iv
            var IVValue = new Rfc2898DeriveBytes("toto", Salt, 16);
            myAes.IV = IVValue.GetBytes(16);

            do
            {
                if(control >= 3){break;}
                Console.WriteLine("Faites un choix : [1] Cripter | [2] Decripter | [3] Sortir.");
                var choix = Console.ReadLine();

                // Protection sur le nombre de chars du choix.
                if(choix.Length > 1){
                    choix = "4";
                    //quit = true;
                }

                if(int.TryParse(choix,out int r)==false){
                    choix = "4";
                    control++;
                    //Console.WriteLine("control " + control);
                }

                var faire = int.Parse(choix);
                switch  (faire){
                    case (int)Rijndael.Fais.CRIPTE:
                        Console.WriteLine("");
                        Console.WriteLine(" [!] ON CHIFFRE : Entrez le texte a chiffrer:");
                        var textoInicial = Console.ReadLine();

                        var res = Encriptacion(textoInicial, myAes);
                        Console.WriteLine($"Resultat chiffré: \n{res}");
                    break;
                    case (int)Rijndael.Fais.DECRIPTE:
                        Console.WriteLine("");
                        Console.WriteLine(" [!] ON DECHIFFRE : Entrez le texte a déchiffrer:");
                        var textoD = Console.ReadLine();

                        var resD = DesEncriptacion(textoD, myAes);
                        Console.WriteLine($"Resultat déchiffré: \n{resD}");
                    break;
                    case (int)Rijndael.Fais.SORTIR:
                        Console.WriteLine("Merci, a bientôt !\n ");
                        quit = true;
                    break;
                    case (int)Rijndael.Fais.ERROR:
                        Console.WriteLine($"Choix erroné ! {control}/3\n");
                    break;
                    default:
                        Console.WriteLine("Entrées incoherentes, sortie...");
                        quit = true;
                    break;
                }
            } while (quit == false);          
        }

        /// <summary>
        /// Chiffre.
        /// </summary>
        /// <param name="textoEncriptado">Texte a chiffrér.</param>
        /// <param name="myAes">Aes instance with Key & IV.</param>
        private static string Encriptacion(string textoInicial, Aes myAes)
        {
            var resultado = "";
            using (myAes)
            {
                // Encrypt the string to an array of bytes.
                byte[] encrypted = MiRijndael.EncryptStringToBytes_Aes(textoInicial, myAes.Key, myAes.IV);
                resultado = Encoding.UTF8.GetString(encrypted);

                // Sauvegarde de la dernière encryptation.
                System.IO.File.WriteAllText("TEXTE.txt", Encoding.UTF8.GetString(encrypted));
                //Console.WriteLine($" Resultat chiffré de {textoInicial}: \n{Encoding.UTF8.GetString(encrypted)}");
            }
            return resultado;
        }

        /// <summary>
        /// Decrypte.
        /// </summary>
        /// <param name="textoEncriptado">Texte chiffré.</param>
        /// <param name="myAes">Aes instance with Key & IV.</param>
        private static string DesEncriptacion(string textoEncriptado, Aes myAes) // TODO: Vérifier le PADDING !!!
        {
            byte[] decriptetexto = System.Text.Encoding.UTF8.GetBytes(textoEncriptado);
            var resultado = MiRijndael.DecryptStringFromBytes_Aes(decriptetexto, myAes.Key, myAes.IV);
            return resultado;
        }
    }
}
